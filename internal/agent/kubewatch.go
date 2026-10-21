package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

// kubeWatcher follows the logs of the pods that rules select with a
// `kubernetes:` source. Every rescan it lists the pods of each source and
// keeps exactly one stream per running container; each line goes through
// the same engine as file lines, under the path "k8s:<ns>/<pod>/<container>".
type kubeWatcher struct {
	a    *Agent
	kick chan struct{}

	mu        sync.Mutex
	client    *kubeClient
	clientErr string
	streams   map[string]*podStream
	byPath    map[string][]*rules.CompiledRule
	listed    map[string]bool   // sources listed at least once: later pods are new
	sources   map[string]string // source key -> last error ("" when fine)
	pods      map[string]int    // source key -> pods selected
	resume    map[string]Position
	streamCtx context.Context
	wg        sync.WaitGroup
}

// podStream is one container's log being followed.
type podStream struct {
	path, ns, pod, container string
	cancel                   context.CancelFunc

	mu      sync.Mutex
	last    time.Time // timestamp of the last line handled
	since   time.Time // where to resume when no line was seen yet
	lines   atomic.Uint64
	bytes   atomic.Int64
	open    atomic.Bool
	lastErr atomic.Pointer[string]
}

func (s *podStream) lastTime() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func k8sPath(ns, pod, container string) string { return "k8s:" + ns + "/" + pod + "/" + container }

func newKubeWatcher(a *Agent) *kubeWatcher {
	return &kubeWatcher{a: a, kick: make(chan struct{}, 1), streams: map[string]*podStream{},
		byPath: map[string][]*rules.CompiledRule{}, listed: map[string]bool{}, sources: map[string]string{}, pods: map[string]int{}}
}

// trigger asks for a sync soon, e.g. after rules changed.
func (w *kubeWatcher) trigger() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// paths returns the stream paths and the rules reading them. It is called
// with a.mu held.
func (w *kubeWatcher) paths() map[string][]*rules.CompiledRule {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string][]*rules.CompiledRule, len(w.byPath))
	for p, rs := range w.byPath {
		out[p] = rs
	}
	return out
}

func (w *kubeWatcher) run(ctx context.Context) {
	resume := w.a.takeKubeResume() // before w.mu: the agent's lock comes first
	w.mu.Lock()
	w.streamCtx = ctx
	w.resume = resume
	w.mu.Unlock()
	t := time.NewTicker(w.a.cfg.RescanInterval.D())
	defer t.Stop()
	for {
		w.sync(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.kick:
		}
	}
}

// stop ends every stream and waits for them (their last lines are handled).
func (w *kubeWatcher) stop() {
	w.mu.Lock()
	for _, s := range w.streams {
		s.cancel()
	}
	w.mu.Unlock()
	w.wg.Wait()
}

type kubeSource struct {
	src   rules.KubernetesSource
	rules []*rules.CompiledRule
}

func (w *kubeWatcher) sync(ctx context.Context) {
	active := w.a.Active()
	sources := map[string]*kubeSource{}
	for _, r := range active.Rules {
		if r.Kubernetes == nil {
			continue
		}
		k := r.Kubernetes.Key()
		if sources[k] == nil {
			sources[k] = &kubeSource{src: *r.Kubernetes}
		}
		sources[k].rules = append(sources[k].rules, r)
	}

	if len(sources) > 0 {
		w.mu.Lock()
		needClient := w.client == nil
		w.mu.Unlock()
		if needClient {
			c, err := newKubeClient(w.a.cfg.Kubernetes)
			w.mu.Lock()
			if err != nil {
				if w.clientErr != err.Error() {
					w.a.tailError("kubernetes", err)
				}
				w.clientErr = err.Error()
				w.mu.Unlock()
				return
			}
			w.client, w.clientErr = c, ""
			w.mu.Unlock()
		}
	}

	type want struct {
		ns, pod, container string
		rules              []*rules.CompiledRule
		fresh              bool // a pod that appeared after its source was first listed
	}
	desired := map[string]*want{}
	keep := map[string]bool{} // streams of sources that could not be listed this time
	for key, s := range sources {
		pods, err := w.client.listPods(ctx, s.src.Namespace, s.src.Selector)
		w.mu.Lock()
		prevErr := w.sources[key]
		if err != nil {
			w.sources[key] = err.Error()
			for p, st := range w.streams {
				if w.inSource(st, s) {
					keep[p] = true
				}
			}
			w.mu.Unlock()
			if prevErr != err.Error() && ctx.Err() == nil {
				w.a.tailError("k8s: "+s.src.String(), err)
			}
			continue
		}
		w.sources[key] = ""
		w.pods[key] = len(pods)
		listedBefore := w.listed[key]
		w.listed[key] = true
		for _, p := range pods {
			for _, c := range p.Containers {
				if s.src.Container != "" && c != s.src.Container {
					continue
				}
				path := k8sPath(p.Namespace, p.Name, c)
				d := desired[path]
				if d == nil {
					_, streaming := w.streams[path]
					d = &want{ns: p.Namespace, pod: p.Name, container: c, fresh: listedBefore && !streaming}
					desired[path] = d
				}
				d.rules = append(d.rules, s.rules...)
			}
		}
		w.mu.Unlock()
	}
	for k := range w.listedKeys() {
		if sources[k] == nil {
			w.forget(k)
		}
	}

	// Cap the number of streams; the rest is reported, not followed.
	max := w.a.cfg.Kubernetes.MaxStreams
	if len(desired) > max {
		names := make([]string, 0, len(desired))
		for p := range desired {
			names = append(names, p)
		}
		sort.Strings(names)
		for _, p := range names[max:] {
			delete(desired, p)
		}
		w.a.tailError("kubernetes", fmt.Errorf("%d container logs selected, following only %d (kubernetes.max_streams)", len(names), max))
	}

	w.mu.Lock()
	changed := false
	byPath := map[string][]*rules.CompiledRule{}
	for p, d := range desired {
		byPath[p] = d.rules
		if _, ok := w.streams[p]; !ok {
			w.start(p, d.ns, d.pod, d.container, d.fresh)
			changed = true
		}
	}
	for p, s := range w.streams {
		if desired[p] == nil && !keep[p] {
			s.cancel()
			delete(w.streams, p)
			changed = true
		} else if keep[p] {
			byPath[p] = w.byPath[p]
		}
	}
	if !changed && !sameRules(byPath, w.byPath) {
		changed = true
	}
	w.byPath = byPath
	w.mu.Unlock()

	if changed {
		w.a.mu.Lock()
		w.a.reconcile(false)
		w.a.mu.Unlock()
	}
}

func (w *kubeWatcher) inSource(st *podStream, s *kubeSource) bool {
	if s.src.Namespace != "*" && st.ns != s.src.Namespace {
		return false
	}
	return s.src.Container == "" || st.container == s.src.Container
}

func (w *kubeWatcher) listedKeys() map[string]bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]bool, len(w.listed))
	for k := range w.listed {
		out[k] = true
	}
	return out
}

func (w *kubeWatcher) forget(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.listed, key)
	delete(w.sources, key)
	delete(w.pods, key)
}

func sameRules(a, b map[string][]*rules.CompiledRule) bool {
	if len(a) != len(b) {
		return false
	}
	for p, ra := range a {
		rb, ok := b[p]
		if !ok || len(ra) != len(rb) {
			return false
		}
		for i := range ra {
			if ra[i] != rb[i] {
				return false
			}
		}
	}
	return true
}

// start launches a stream; callers hold w.mu.
func (w *kubeWatcher) start(path, ns, pod, container string, fresh bool) {
	parent := w.streamCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	s := &podStream{path: path, ns: ns, pod: pod, container: container, cancel: cancel}
	if pos, ok := w.resume[path]; ok {
		s.last = pos.TS
		delete(w.resume, path)
	}
	fromEnd := s.last.IsZero() && !fresh && w.a.cfg.StartFrom != "beginning"
	w.streams[path] = s
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.follow(ctx, s, fromEnd)
	}()
}

// follow reads one container's log until ctx ends, reconnecting when the
// stream drops (API server timeouts, container restarts).
func (w *kubeWatcher) follow(ctx context.Context, s *podStream, fromEnd bool) {
	backoff := time.Second
	for ctx.Err() == nil {
		w.mu.Lock()
		client := w.client
		w.mu.Unlock()
		since := s.lastTime()
		if since.IsZero() {
			since = s.since
		}
		connected := time.Now()
		body, err := client.followLog(ctx, s.ns, s.pod, s.container, since, fromEnd && since.IsZero())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.fail(err, w.a)
			sleepCtx(ctx, backoff)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		s.open.Store(true)
		s.lastErr.Store(nil)
		if s.since.IsZero() {
			s.since = connected // a reconnect before any line resumes from here
		}
		w.read(ctx, s, body)
		body.Close()
		s.open.Store(false)
		sleepCtx(ctx, 2*time.Second) // the container may have stopped; the next sync decides
	}
}

func (s *podStream) fail(err error, a *Agent) {
	msg := err.Error()
	if p := s.lastErr.Load(); p != nil && *p == msg {
		return
	}
	s.lastErr.Store(&msg)
	a.tailError(s.path, err)
}

// read handles "<RFC3339Nano timestamp> <line>" lines until the stream ends.
func (w *kubeWatcher) read(ctx context.Context, s *podStream, body io.Reader) {
	maxLine := w.a.cfg.MaxLineBytes
	r := bufio.NewReaderSize(body, 64*1024)
	var long []byte
	for ctx.Err() == nil {
		chunk, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			if len(long) < maxLine+64 {
				long = append(long, chunk[:min(len(chunk), maxLine+64-len(long))]...)
			}
			continue
		}
		if err != nil && len(chunk) == 0 {
			return
		}
		line := chunk
		if long != nil {
			line = append(long, chunk[:min(len(chunk), max(0, maxLine+64-len(long)))]...)
			long = nil
		}
		s.bytes.Add(int64(len(chunk)))
		line = bytes.TrimRight(line, "\r\n")
		sp := bytes.IndexByte(line, ' ')
		if sp <= 0 {
			continue
		}
		ts, perr := time.Parse(time.RFC3339Nano, string(line[:sp]))
		if perr != nil {
			continue
		}
		s.mu.Lock()
		dup := !s.last.IsZero() && !ts.After(s.last)
		s.mu.Unlock()
		if dup {
			continue // already handled before a reconnect
		}
		text := line[sp+1:]
		if len(text) > maxLine {
			text = text[:maxLine]
		}
		w.a.eng.process(s.path, text)
		s.lines.Add(1)
		s.mu.Lock()
		s.last = ts
		s.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// positions returns the resume point of every stream, for the state file.
func (w *kubeWatcher) positions() map[string]Position {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]Position{}
	for p, s := range w.streams {
		if t := s.lastTime(); !t.IsZero() {
			out[p] = Position{TS: t}
		}
	}
	return out
}

// KubeStatus reports the Kubernetes sources on the status page.
type KubeStatus struct {
	Error   string             `json:"error,omitempty"`
	Sources []KubeSourceStatus `json:"sources"`
}

type KubeSourceStatus struct {
	Namespace string `json:"namespace"`
	Selector  string `json:"selector,omitempty"`
	Container string `json:"container,omitempty"`
	Pods      int    `json:"pods"`
	Error     string `json:"error,omitempty"`
}

// status returns nil when no rule reads Kubernetes, plus the streams as files.
func (w *kubeWatcher) status(active *rules.Compiled) (*KubeStatus, []FileStatus) {
	seen := map[string]bool{}
	var srcs []rules.KubernetesSource
	for _, r := range active.Rules {
		if r.Kubernetes != nil && !seen[r.Kubernetes.Key()] {
			seen[r.Kubernetes.Key()] = true
			srcs = append(srcs, *r.Kubernetes)
		}
	}
	if len(srcs) == 0 {
		return nil, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	ks := &KubeStatus{Error: w.clientErr}
	for _, src := range srcs {
		ks.Sources = append(ks.Sources, KubeSourceStatus{Namespace: src.Namespace, Selector: src.Selector, Container: src.Container,
			Pods: w.pods[src.Key()], Error: w.sources[src.Key()]})
	}
	var files []FileStatus
	for p, s := range w.streams {
		fs := FileStatus{Path: p, Open: s.open.Load(), Offset: s.bytes.Load(), Lines: s.lines.Load()}
		if e := s.lastErr.Load(); e != nil && !s.open.Load() {
			fs.Error = *e
		}
		for _, r := range w.byPath[p] {
			fs.Rules = append(fs.Rules, r.Name)
		}
		files = append(files, fs)
	}
	return ks, files
}
