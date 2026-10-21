package agent

import (
	"bufio"
	"container/heap"
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

// A dry run replays the last part of the agent's log files through a
// candidate rule set and reports what it would have sent, next to what the
// current rules sent: "would have fired 340 alerts in the last hour".
//
// To know where "an hour ago" is in each file, the agent samples every
// file's read position once a minute into a small fixed ring per file. Line
// times between two samples are interpolated by byte offset, which is what
// suppression windows and absence rules need to be simulated faithfully.

const (
	histInterval = time.Minute
	// MaxDryRunWindow is how far back a dry run can look.
	MaxDryRunWindow = 3 * time.Hour
	histSize        = int(MaxDryRunWindow/histInterval) + 2 // ~3 KB per file

	// dryRunMaxBytes caps how much of one file a dry run reads; for a busier
	// file only the newest part of the window is replayed.
	dryRunMaxBytes = 256 << 20
	// dryRunNoHistoryBytes is how much of a file without position history
	// (not watched by the current rules) is read.
	dryRunNoHistoryBytes = 16 << 20
	dryRunSamples        = 3
)

var ErrDryRunBusy = errors.New("another dry run is running on this agent; try again in a moment")

type offsetSample struct {
	t   int64 // unix nanoseconds
	off int64
}

// offsetHist is a fixed-size ring of position samples for one file.
type offsetHist struct {
	buf     [histSize]offsetSample
	n, next int
}

func (h *offsetHist) add(s offsetSample) {
	if h.n > 0 && s.off < h.buf[(h.next-1+histSize)%histSize].off {
		h.n, h.next = 0, 0 // rotated or truncated: older samples describe another file
	}
	h.buf[h.next] = s
	h.next = (h.next + 1) % histSize
	if h.n < histSize {
		h.n++
	}
}

// samples returns the samples, oldest first.
func (h *offsetHist) samples() []offsetSample {
	out := make([]offsetSample, 0, h.n)
	for i := h.n; i > 0; i-- {
		out = append(out, h.buf[(h.next-i+histSize)%histSize])
	}
	return out
}

// sampleOffsets records where every watched file is now.
func (a *Agent) sampleOffsets(now time.Time) {
	a.mu.Lock()
	offs := make(map[string]int64, len(a.tailers))
	for p, h := range a.tailers {
		if h.t.opened.Load() {
			offs[p] = h.t.offset.Load()
		} else {
			offs[p] = -1
		}
	}
	a.mu.Unlock()

	a.histMu.Lock()
	defer a.histMu.Unlock()
	for p := range a.hist {
		if _, ok := offs[p]; !ok {
			delete(a.hist, p)
		}
	}
	for p, off := range offs {
		if off < 0 {
			continue
		}
		h := a.hist[p]
		if h == nil {
			h = &offsetHist{}
			a.hist[p] = h
		}
		h.add(offsetSample{now.UnixNano(), off})
	}
}

func (a *Agent) history(path string) []offsetSample {
	a.histMu.Lock()
	defer a.histMu.Unlock()
	if h := a.hist[path]; h != nil {
		return h.samples()
	}
	return nil
}

// DryRunRule is what one rule would have done.
type DryRunRule struct {
	Name       string   `json:"name"`
	Matches    uint64   `json:"matches"`
	Alerts     int      `json:"alerts"` // alerts it would have sent, summaries included
	Suppressed uint64   `json:"suppressed"`
	Samples    []string `json:"samples,omitempty"`
}

type DryRunSet struct {
	Hash   string       `json:"hash"`
	Alerts int          `json:"alerts"`
	Rules  []DryRunRule `json:"rules"`
}

type DryRunFile struct {
	Path  string    `json:"path"`
	Bytes int64     `json:"bytes"`
	Lines int64     `json:"lines"`
	From  time.Time `json:"from"` // oldest line time covered
	// Truncated: the window held more than the scan limit, so only its
	// newest part was replayed.
	Truncated bool `json:"truncated,omitempty"`
	// Estimated: there is no position history for the file (not watched
	// yet, or the agent just started), so its tail was read and line times
	// spread evenly.
	Estimated bool   `json:"estimated,omitempty"`
	Error     string `json:"error,omitempty"`
}

type DryRunResult struct {
	Window    string       `json:"window"`
	From      time.Time    `json:"from"`
	To        time.Time    `json:"to"`
	Files     []DryRunFile `json:"files"`
	Current   DryRunSet    `json:"current"`
	Candidate DryRunSet    `json:"candidate"`
	// Partial: the request deadline hit before every line was replayed.
	Partial bool  `json:"partial,omitempty"`
	TookMS  int64 `json:"took_ms"`
}

// DryRun replays the last window of the log files through candidate and
// through the current rules (the rules file, without the local overlay).
// Nothing is sent. Memory stays bounded: lines are streamed, and the
// simulated suppression tables have the same cap as the live ones.
func (a *Agent) DryRun(ctx context.Context, candidate *rules.Compiled, window time.Duration) (*DryRunResult, error) {
	select {
	case a.dryRuns <- struct{}{}:
		defer func() { <-a.dryRuns }()
	default:
		return nil, ErrDryRunBusy
	}
	if window <= 0 || window > MaxDryRunWindow {
		window = time.Hour
	}
	start := time.Now()
	now := start
	from := now.Add(-window)
	current := a.Rules()
	res := &DryRunResult{Window: window.String(), From: from, To: now,
		Current: DryRunSet{Hash: current.Hash}, Candidate: DryRunSet{Hash: candidate.Hash}}

	paths := map[string]bool{}
	for _, c := range []*rules.Compiled{current, candidate} {
		for _, r := range c.Rules {
			for _, pat := range r.Files {
				for _, p := range expandPath(pat) {
					paths[p] = true
				}
			}
		}
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)

	// Sources point into res.Files, so it must not grow past its capacity.
	res.Files = make([]DryRunFile, 0, len(sorted))
	var h sourceHeap
	for _, p := range sorted {
		src, info := a.openDryRunSource(p, from, now)
		res.Files = append(res.Files, *info)
		if src != nil {
			defer src.f.Close()
			src.info = &res.Files[len(res.Files)-1]
			if src.next() {
				h = append(h, src)
			}
		}
	}
	heap.Init(&h)

	clock := from
	cur := newDryEngine(a, current, sorted, &clock, &res.Current)
	cand := newDryEngine(a, candidate, sorted, &clock, &res.Candidate)
	lastSweep := clock
	for n := 0; h.Len() > 0; n++ {
		if n%4096 == 0 && ctx.Err() != nil {
			res.Partial = true
			break
		}
		src := h[0]
		if src.t.After(clock) {
			clock = src.t
		}
		if clock.Sub(lastSweep) >= time.Second {
			cur.e.sweep()
			cand.e.sweep()
			lastSweep = clock
		}
		if !src.t.Before(from) {
			cur.e.process(src.path, src.line)
			cand.e.process(src.path, src.line)
		}
		if src.next() {
			heap.Fix(&h, 0)
		} else {
			heap.Pop(&h)
		}
	}
	if !res.Partial {
		clock = now
		cur.e.sweep()
		cand.e.sweep()
	}
	cur.finish()
	cand.finish()
	for i := range res.Files {
		if res.Files[i].From.Before(from) {
			res.Files[i].From = from
		}
	}
	// Pod logs live in the cluster, not on this disk: say so instead of
	// silently counting nothing for those rules.
	seen := map[string]bool{}
	for _, c := range []*rules.Compiled{current, candidate} {
		for _, r := range c.Rules {
			if k := r.Kubernetes; k != nil && !seen[k.Key()] {
				seen[k.Key()] = true
				res.Files = append(res.Files, DryRunFile{Path: "k8s: " + k.String(), From: from,
					Error: "dry runs replay files only; this rule's Kubernetes pod logs were not replayed"})
			}
		}
	}
	res.TookMS = time.Since(start).Milliseconds()
	return res, nil
}

// dryEngine is an engine that counts alerts instead of sending them.
type dryEngine struct {
	e     *engine
	c     *rules.Compiled
	set   *DryRunSet
	rules map[string]*DryRunRule
}

func newDryEngine(a *Agent, c *rules.Compiled, files []string, clock *time.Time, set *DryRunSet) *dryEngine {
	d := &dryEngine{c: c, set: set, rules: map[string]*DryRunRule{}}
	for _, r := range c.Rules {
		d.rules[r.Name] = &DryRunRule{Name: r.Name}
	}
	d.e = newEngine(a.cfg.Name, a.host, newRing(1), func(al Alert, r *rules.CompiledRule) {
		dr := d.rules[r.Name]
		dr.Alerts++
		set.Alerts++
		if len(dr.Samples) < dryRunSamples {
			text := al.Text
			if len(text) > 300 {
				text = text[:300] + "…"
			}
			dr.Samples = append(dr.Samples, text)
		}
	})
	d.e.now = func() time.Time { return *clock }
	byFile := map[string][]*rules.CompiledRule{}
	want := map[string]bool{}
	for _, f := range files {
		want[f] = true
	}
	for _, r := range c.Rules {
		for _, pat := range r.Files {
			for _, p := range expandPath(pat) {
				if want[p] {
					byFile[p] = append(byFile[p], r)
				}
			}
		}
	}
	d.e.setSnapshot(&snapshot{rules: c, byFile: byFile})
	return d
}

func (d *dryEngine) finish() {
	stats := d.e.ruleStats()
	d.set.Rules = make([]DryRunRule, 0, len(d.c.Rules))
	for _, r := range d.c.Rules {
		dr := d.rules[r.Name]
		st := stats[r.Name]
		dr.Matches, dr.Suppressed = st.Matches, st.Suppressed
		d.set.Rules = append(d.set.Rules, *dr)
	}
}

// dryRunSource streams the lines of one file's window with their estimated times.
type dryRunSource struct {
	path    string
	f       *os.File
	r       *bufio.Reader
	info    *DryRunFile
	pts     []offsetSample // (time, offset) points to interpolate between
	seg     int
	pos     int64 // offset of the next unread byte
	end     int64
	skip    bool // the window starts mid-line: drop that partial line
	maxLine int
	buf     []byte

	line []byte // valid until the next call to next
	t    time.Time
}

func (a *Agent) openDryRunSource(path string, from, now time.Time) (*dryRunSource, *DryRunFile) {
	info := &DryRunFile{Path: path, From: from}
	f, err := openShared(path)
	if err != nil {
		info.Error = err.Error()
		return nil, info
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		info.Error = err.Error()
		return nil, info
	}
	size := fi.Size()
	nowS := offsetSample{now.UnixNano(), size}

	var start int64
	var pts []offsetSample
	samples := a.history(path)
	if len(samples) == 0 || samples[len(samples)-1].off > size {
		// No usable history (a file the rules do not watch yet, or an agent
		// that started less than a minute ago): read the tail and spread it
		// evenly over the window, or over the agent's uptime if shorter.
		start = max(0, size-dryRunNoHistoryBytes)
		first := from
		if a.started.After(first) {
			first = a.started
		}
		pts = []offsetSample{{first.UnixNano(), start}, nowS}
		info.Estimated = true
	} else {
		k := 0
		for i, s := range samples {
			if s.t <= from.UnixNano() {
				k = i
			}
		}
		start = samples[k].off
		pts = append(samples[k:len(samples):len(samples)], nowS)
	}
	if size-start > dryRunMaxBytes {
		start = size - dryRunMaxBytes
		info.Truncated = true
	}
	src := &dryRunSource{path: path, f: f, pts: pts, pos: start, end: size, maxLine: a.cfg.MaxLineBytes}
	info.From = src.timeAt(start)
	info.Bytes = size - start
	if start > 0 {
		var b [1]byte
		if _, err := f.ReadAt(b[:], start-1); err == nil && b[0] != '\n' {
			src.skip = true
		}
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		f.Close()
		info.Error = err.Error()
		return nil, info
	}
	src.r = bufio.NewReaderSize(io.LimitReader(f, size-start), 64*1024)
	return src, info
}

// next reads the next complete line. A trailing line without a newline is
// still being written and is left for later, like the tailer does.
func (s *dryRunSource) next() bool {
	for {
		lineStart := s.pos
		chunk, err := s.r.ReadSlice('\n')
		s.pos += int64(len(chunk))
		var line []byte
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			s.buf = append(s.buf[:0], chunk[:min(len(chunk), s.maxLine)]...)
			for errors.Is(err, bufio.ErrBufferFull) {
				chunk, err = s.r.ReadSlice('\n')
				s.pos += int64(len(chunk))
			}
			if err != nil {
				return false
			}
			line = s.buf
		case err != nil:
			return false
		default:
			line = chunk[:len(chunk)-1]
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			if len(line) > s.maxLine {
				line = line[:s.maxLine]
			}
		}
		if s.skip {
			s.skip = false
			continue
		}
		s.line, s.t = line, s.timeAt(lineStart)
		s.info.Lines++
		return true
	}
}

// timeAt interpolates the time a byte offset was written. Offsets only grow,
// so the segment pointer only moves forward.
func (s *dryRunSource) timeAt(off int64) time.Time {
	for s.seg+2 < len(s.pts) && s.pts[s.seg+1].off <= off {
		s.seg++
	}
	a, b := s.pts[s.seg], s.pts[min(s.seg+1, len(s.pts)-1)]
	if b.off <= a.off || off <= a.off {
		return time.Unix(0, a.t)
	}
	if off >= b.off {
		return time.Unix(0, b.t)
	}
	return time.Unix(0, a.t+int64(float64(b.t-a.t)*float64(off-a.off)/float64(b.off-a.off)))
}

// sourceHeap orders sources by the time of their current line, so lines from
// all files are replayed in (estimated) time order.
type sourceHeap []*dryRunSource

func (h sourceHeap) Len() int           { return len(h) }
func (h sourceHeap) Less(i, j int) bool { return h[i].t.Before(h[j].t) }
func (h sourceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *sourceHeap) Push(x any)        { *h = append(*h, x.(*dryRunSource)) }
func (h *sourceHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}
