// Package agent implements the grepalert agent: it tails log files, matches
// lines against hot-reloadable rules, suppresses floods and posts alerts to
// webhooks.
package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
	"github.com/fadhaw/grepalert/internal/version"
)

// Version is the release version (set at build time, see internal/version).
var Version = version.Version

type Agent struct {
	cfg     Config
	log     *slog.Logger
	host    string
	started time.Time

	events  *ring
	eng     *engine
	notif   *notifier
	conn    *connector // nil unless dashboard.url is set
	connErr error

	mu            sync.Mutex      // guards everything below
	rules         *rules.Compiled // the rules file: the group's rules when a dashboard manages them
	rulesLoadedAt time.Time
	rulesOrigin   string
	// Local overlay: this machine's extra rules, merged on top of rules.
	localRaw  []byte
	localHash string
	localErr  string
	active    *rules.Compiled // rules plus the overlay; what actually runs
	tailers   map[string]*tailerHandle
	resume    map[string]Position // saved positions not yet handed to a tailer
	noMatch   map[string]string   // file pattern -> why it matches nothing, as last logged
	stopped   bool
	sched     *scheduler   // polls all tailers on a fixed worker pool
	kube      *kubeWatcher // follows the pods of rules with a kubernetes source

	lastState    []byte // last state written, to skip identical writes
	rejectedHash string // rules file version that failed validation (Run goroutine only)

	histMu  sync.Mutex
	hist    map[string]*offsetHist // per file: where it was each minute, for dry runs
	dryRuns chan struct{}          // one dry run at a time
}

type tailerHandle struct {
	t *tailer
}

func New(cfg Config, log *slog.Logger) *Agent {
	cfg.setDefaults()
	host, _ := os.Hostname()
	if cfg.Name == "" {
		cfg.Name = host
	}
	a := &Agent{
		cfg:     cfg,
		log:     log,
		host:    host,
		started: time.Now(),
		events:  newRing(cfg.EventBuffer),
		tailers: map[string]*tailerHandle{},
		noMatch: map[string]string{},
		rules:   &rules.Compiled{Hash: rules.Hash(nil), Webhooks: map[string]*rules.CompiledWebhook{}},
		hist:    map[string]*offsetHist{},
		dryRuns: make(chan struct{}, 1),
	}
	a.active = a.rules
	a.notif = newNotifier(cfg.QueueSize, cfg.Retries, a.events)
	a.eng = newEngine(cfg.Name, host, a.events, a.notif.enqueue)
	a.sched = newScheduler(cfg.ReadWorkers, cfg.PollInterval.D(), cfg.IdlePollInterval.D())
	a.kube = newKubeWatcher(a)
	if cfg.Dashboard.URL != "" {
		a.conn, a.connErr = newConnector(a)
		if a.conn != nil {
			// Alerts go through the dashboard, directly only as a fallback.
			a.notif.route = a.conn.offer
			a.notif.silenced = a.conn.silenced
			a.conn.fallback = a.notif.fallbackDeliver
		}
	}
	return a
}

// Run loads the rules file, starts tailing and blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if a.cfg.MemoryLimit > 0 {
		debug.SetMemoryLimit(int64(a.cfg.MemoryLimit))
	}
	// The notifier outlives ctx: on shutdown it is stopped only after the
	// tailers, so alerts for the last lines read are still delivered.
	notifCtx, stopNotif := context.WithCancel(context.Background())
	defer stopNotif()
	a.notif.start(notifCtx, a.cfg.Workers)

	if a.stateEnabled() {
		pos, err := loadState(a.cfg.StateFile)
		if err != nil {
			a.log.Warn("cannot read state file, starting without saved positions", "path", a.cfg.StateFile, "err", err)
		}
		a.mu.Lock()
		a.resume = pos
		a.mu.Unlock()
		if len(pos) > 0 {
			a.log.Info("loaded saved file positions", "files", len(pos), "path", a.cfg.StateFile)
		}
	}

	if a.connErr != nil {
		return a.connErr
	}
	a.loadLocalFile()
	if err := a.loadRulesFile(true); err != nil {
		return err
	}
	if a.conn != nil {
		a.conn.start(ctx)
	}
	go a.kube.run(ctx)

	tick := time.NewTicker(a.cfg.RescanInterval.D())
	defer tick.Stop()
	sweep := time.NewTicker(time.Second)
	defer sweep.Stop()
	saveEvery := a.cfg.StateInterval.D()
	if !a.stateEnabled() {
		saveEvery = time.Hour // ticker needs a positive interval; saves are no-ops
	}
	save := time.NewTicker(saveEvery)
	defer save.Stop()
	sample := time.NewTicker(histInterval)
	defer sample.Stop()
	for {
		select {
		case <-ctx.Done():
			a.mu.Lock()
			a.stopped = true
			handles := make([]*tailerHandle, 0, len(a.tailers))
			for _, h := range a.tailers {
				handles = append(handles, h)
			}
			a.mu.Unlock()
			a.sched.stop() // final read of every file, then close
			a.kube.stop()  // pod log streams end with the context
			if a.conn != nil {
				a.conn.flushAlerts() // hand the last alerts to the dashboard (or send them)
				a.conn.wait(5 * time.Second)
			}
			stopNotif()
			a.notif.wait()
			// Save after the tailers stopped, so the final positions are exact.
			a.saveState(handles)
			return nil
		case <-save.C:
			a.saveState(nil)
		case now := <-sample.C:
			a.sampleOffsets(now)
		case <-sweep.C:
			a.eng.sweep()
		case <-tick.C:
			if err := a.loadRulesFile(false); err != nil {
				a.log.Error("rules file reload failed, keeping previous rules", "err", err)
			}
			a.loadLocalFile()
			a.mu.Lock()
			a.reconcile(true)
			a.mu.Unlock()
		}
	}
}

// loadRulesFile (re)loads the rules file if its content changed, so edits made
// directly on disk are picked up without a restart.
func (a *Agent) loadRulesFile(initial bool) error {
	raw, err := os.ReadFile(a.cfg.RulesFile)
	if errors.Is(err, fs.ErrNotExist) && initial {
		a.log.Warn("rules file does not exist yet, starting with no rules", "path", a.cfg.RulesFile)
		raw, err = nil, nil
	}
	if err != nil {
		return err
	}
	hash := rules.Hash(raw)
	a.mu.Lock()
	same := a.rules != nil && a.rules.Hash == hash
	a.mu.Unlock()
	// A file that was rejected is reported once, not on every check.
	if same || (!initial && hash == a.rejectedHash) {
		return nil
	}
	_, err = a.apply(raw, "file", false)
	if err != nil {
		a.rejectedHash = hash
		if !initial {
			a.events.add(Event{Time: time.Now(), Type: "rules", Message: "rules file rejected: " + err.Error()})
		}
	} else {
		a.rejectedHash = ""
	}
	return err
}

// ApplyRules validates raw, persists it to the rules file and activates it.
// On validation failure nothing changes. changed is false when raw is identical
// to the active rules, in which case nothing is done.
//
// The first time a dashboard group pushes its rules (origin "group:<name>"),
// the agent's own rules are saved to rules.before-group.yaml so they can be
// restored when it leaves the group. Any other change (a direct edit while
// ungrouped) makes the new rules the agent's own, and drops that copy.
func (a *Agent) ApplyRules(raw []byte, origin string) (c *rules.Compiled, changed bool, err error) {
	if cur := a.Rules(); cur.Hash == rules.Hash(raw) {
		return cur, false, nil
	}
	fromGroup := strings.HasPrefix(origin, "group:")
	if fromGroup {
		if _, err := rules.Parse(raw); err != nil {
			return nil, false, err // a rejected push replaces nothing, so saves nothing
		}
		a.saveOwnRules()
	}
	c, err = a.apply(raw, origin, true)
	if err == nil && !fromGroup {
		os.Remove(a.ownRulesPath())
	}
	return c, err == nil, err
}

func (a *Agent) ownRulesPath() string {
	return filepath.Join(filepath.Dir(a.cfg.RulesFile), "rules.before-group.yaml")
}

// saveOwnRules keeps a copy of the rules file before a group replaces it,
// unless a copy already exists (it is then the agent's own rules from before
// its first group) or there is nothing to keep.
func (a *Agent) saveOwnRules() {
	path := a.ownRulesPath()
	if _, err := os.Stat(path); err == nil {
		return
	}
	cur, err := os.ReadFile(a.cfg.RulesFile)
	if err != nil || len(bytes.TrimSpace(cur)) == 0 {
		return
	}
	if err := writeFileAtomic(path, cur); err != nil {
		a.log.Warn("cannot save the agent's own rules before the group's replace them", "path", path, "err", err)
		return
	}
	a.log.Info("saved the agent's own rules before a group replaced them", "path", path, "hash", rules.Hash(cur))
	a.events.add(Event{Time: time.Now(), Type: "rules", Message: "own rules " + rules.Hash(cur) + " saved to " + path + " before the group's rules replaced them"})
}

// OwnRules returns the agent's own rules saved when a group replaced them.
func (a *Agent) OwnRules() ([]byte, bool) {
	raw, err := os.ReadFile(a.ownRulesPath())
	return raw, err == nil
}

// RestoreOwnRules makes the saved own rules the active rules again.
func (a *Agent) RestoreOwnRules() (*rules.Compiled, error) {
	raw, ok := a.OwnRules()
	if !ok {
		return nil, errors.New("there are no saved rules from before a group")
	}
	c, _, err := a.ApplyRules(raw, "restored")
	if err != nil {
		return nil, fmt.Errorf("the saved rules no longer validate: %w", err)
	}
	os.Remove(a.ownRulesPath()) // also when they were already active
	return c, nil
}

func (a *Agent) apply(raw []byte, origin string, persist bool) (*rules.Compiled, error) {
	c, err := rules.Parse(raw)
	if err != nil {
		return nil, err
	}
	if persist {
		if err := writeFileAtomic(a.cfg.RulesFile, raw); err != nil {
			return nil, fmt.Errorf("persist rules: %w", err)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = c
	a.rulesLoadedAt = time.Now()
	a.rulesOrigin = origin
	a.rebuild()
	a.reconcile(false)
	a.kube.trigger() // pods of new or changed kubernetes sources
	a.log.Info("rules applied", "hash", c.Hash, "rules", len(c.Rules), "origin", origin)
	a.events.add(Event{Time: time.Now(), Type: "rules",
		Message: fmt.Sprintf("rules %s applied from %s (%d active rules)", c.Hash, origin, len(c.Rules))})
	return c, nil
}

// rebuild merges the local overlay into the rules. If the overlay no longer
// fits (e.g. the group added a rule with the same name), the group's rules
// still run and the overlay is reported as rejected. Callers hold a.mu.
func (a *Agent) rebuild() {
	if len(bytes.TrimSpace(a.localRaw)) == 0 {
		a.active, a.localErr = a.rules, ""
		return
	}
	m, err := rules.ParseOverlay(a.rules.Raw, a.localRaw)
	if err != nil {
		if msg := err.Error(); msg != a.localErr {
			a.log.Error("local rules rejected, running the group's rules only", "err", err)
			a.events.add(Event{Time: time.Now(), Type: "rules", Message: "local rules rejected: " + msg})
		}
		a.active, a.localErr = a.rules, err.Error()
		return
	}
	a.active, a.localErr = m, ""
}

// loadLocalFile (re)reads the local overlay file when it changed on disk.
func (a *Agent) loadLocalFile() {
	if a.cfg.LocalRulesFile == "off" {
		return
	}
	raw, err := os.ReadFile(a.cfg.LocalRulesFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		a.log.Warn("cannot read local rules file", "path", a.cfg.LocalRulesFile, "err", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if bytes.Equal(raw, a.localRaw) {
		return
	}
	a.setLocal(raw, "file")
}

// setLocal installs a new overlay; callers hold a.mu.
func (a *Agent) setLocal(raw []byte, origin string) {
	a.localRaw, a.localHash = raw, rules.Hash(raw)
	a.rebuild()
	a.reconcile(false)
	a.kube.trigger()
	if a.localErr == "" && len(bytes.TrimSpace(raw)) > 0 {
		n := len(a.active.Rules) - len(a.rules.Rules)
		a.log.Info("local rules applied", "hash", a.localHash, "rules", n, "origin", origin)
		a.events.add(Event{Time: time.Now(), Type: "rules",
			Message: fmt.Sprintf("local rules %s applied from %s (%d extra rules)", a.localHash, origin, n)})
	}
}

// LocalRules returns the overlay document, its hash and the reason it is not
// running, if it is not.
func (a *Agent) LocalRules() (raw []byte, hash, rejected string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.localRaw, a.localHash, a.localErr
}

// ApplyLocalRules validates raw against the current rules, persists it to
// the local rules file and activates it. An empty document removes the
// overlay.
func (a *Agent) ApplyLocalRules(raw []byte, origin string) error {
	if a.cfg.LocalRulesFile == "off" {
		return errors.New("local rules are disabled on this agent (local_rules_file: off)")
	}
	a.mu.Lock()
	base := a.rules.Raw
	a.mu.Unlock()
	if len(bytes.TrimSpace(raw)) > 0 {
		if _, err := rules.ParseOverlay(base, raw); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(a.cfg.LocalRulesFile, raw); err != nil {
		return fmt.Errorf("persist local rules: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.setLocal(raw, origin)
	if a.localErr != "" { // the group's rules changed in between
		return errors.New(a.localErr)
	}
	return nil
}

// reconcile expands file globs, starts/stops tailers to match and publishes a
// new snapshot to the engine. Callers must hold a.mu.
//
// discovered is true on periodic re-scans: files that appear then are new and
// are read from the beginning; files picked up because rules changed start at
// the end so old history does not fire a burst of alerts.
func (a *Agent) reconcile(discovered bool) {
	if a.stopped {
		return
	}
	byFile := map[string][]*rules.CompiledRule{}
	patterns := map[string]bool{}
	for _, r := range a.active.Rules {
		for _, pat := range r.Files {
			patterns[pat] = true
			m := expandPath(pat)
			a.noteMatches(pat, len(m))
			for _, p := range m {
				byFile[p] = append(byFile[p], r)
			}
		}
	}
	for pat := range a.noMatch {
		if !patterns[pat] {
			delete(a.noMatch, pat)
		}
	}
	defer func() {
		// Pod log streams are matched like files, but the watcher runs them.
		snap := make(map[string][]*rules.CompiledRule, len(byFile))
		for p, rs := range byFile {
			snap[p] = rs
		}
		for p, rs := range a.kube.paths() {
			snap[p] = rs
		}
		a.eng.setSnapshot(&snapshot{rules: a.active, byFile: snap})
	}()
	for p, h := range a.tailers {
		if _, ok := byFile[p]; !ok {
			a.sched.remove(h.t)
			delete(a.tailers, p)
			a.log.Info("stopped following file", "file", p)
		}
	}
	fromStart := a.cfg.StartFrom == "beginning"
	for p := range byFile {
		if _, ok := a.tailers[p]; ok {
			continue
		}
		// A saved position wins over start_from; it is used once, so a file
		// dropped from the rules and re-added later starts fresh.
		var resume *Position
		if pos, ok := a.resume[p]; ok {
			resume = &pos
			delete(a.resume, p)
		}
		t := newTailer(p, a.cfg.PollInterval.D(), a.cfg.MaxLineBytes, fromStart || discovered, resume,
			a.eng.process, a.tailError, a.log.With("file", p))
		a.tailers[p] = &tailerHandle{t: t}
		a.sched.add(t)

		start := "end"
		switch {
		case resume != nil:
			start = "saved position"
		case fromStart || discovered:
			start = "beginning"
		}
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			start = "beginning, once created" // what a tailer does with a file that appears later
		}
		names := make([]string, 0, len(byFile[p]))
		for _, r := range byFile[p] {
			names = append(names, r.Name)
		}
		a.log.Info("following file", "file", p, "rules", strings.Join(names, ","), "from", start)
	}
}

// noteMatches logs, once per change, that a file pattern matches nothing and
// why (for example a directory the agent may not list), and that it matches
// again later. A problem other than "nothing there yet" is also an event.
// Callers must hold a.mu.
func (a *Agent) noteMatches(pat string, n int) {
	if !strings.ContainsAny(pat, "*?[") {
		return // a literal path: its tailer reports it while it waits
	}
	if n > 0 {
		if _, ok := a.noMatch[pat]; ok {
			delete(a.noMatch, pat)
			a.log.Info("file pattern matches again", "pattern", pat, "files", n)
		}
		return
	}
	why, failed := globProblem(pat)
	if prev, ok := a.noMatch[pat]; ok && prev == why {
		return
	}
	a.noMatch[pat] = why
	if failed {
		a.log.Warn("no files match", "pattern", pat, "reason", why)
		a.events.add(Event{Time: time.Now(), Type: "error", File: pat, Message: "no files match: " + why})
	} else {
		a.log.Info("no files match yet", "pattern", pat, "reason", why)
	}
}

// globProblem explains why pat matches no files, walking it one path element
// at a time like filepath.Glob does, but keeping the errors Glob ignores.
// failed is true when a directory could not be read (rather than simply
// having nothing that matches).
func globProblem(pat string) (why string, failed bool) {
	pat = filepath.Clean(pat)
	vol := filepath.VolumeName(pat)
	parts := strings.Split(pat[len(vol):], string(filepath.Separator))
	base := vol
	if len(parts) > 0 && parts[0] == "" { // absolute path
		base += string(filepath.Separator)
		parts = parts[1:]
	}
	if base == "" {
		base = "."
	}
	dirs := []string{base}
	for _, part := range parts {
		var next []string
		for _, d := range dirs {
			if !strings.ContainsAny(part, "*?[") {
				p := filepath.Join(d, part)
				if _, err := os.Stat(p); err == nil {
					next = append(next, p)
				} else if !errors.Is(err, fs.ErrNotExist) && len(dirs) == 1 {
					return fmt.Sprintf("cannot read %s: %v", p, unwrapPath(err)), true
				}
				continue
			}
			entries, err := os.ReadDir(d)
			if err != nil {
				return fmt.Sprintf("cannot list %s: %v", d, unwrapPath(err)), true
			}
			for _, e := range entries {
				if ok, _ := filepath.Match(part, e.Name()); ok {
					next = append(next, filepath.Join(d, e.Name()))
				}
			}
		}
		if len(next) == 0 {
			where := dirs[0]
			if len(dirs) > 1 {
				where = fmt.Sprintf("%s and %d more", dirs[0], len(dirs)-1)
			}
			return fmt.Sprintf("nothing named %q in %s", part, where), false
		}
		dirs = next
	}
	return "matches appeared while checking", false
}

func unwrapPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// takeKubeResume hands the saved positions of pod log streams to the
// Kubernetes watcher (once, at start).
func (a *Agent) takeKubeResume() map[string]Position {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]Position{}
	for p, pos := range a.resume {
		if strings.HasPrefix(p, "k8s:") {
			out[p] = pos
			delete(a.resume, p)
		}
	}
	return out
}

// expandPath returns glob matches, or the literal path when it has no glob
// characters (so we wait for files that do not exist yet).
func expandPath(pat string) []string {
	if !strings.ContainsAny(pat, "*?[") {
		return []string{filepath.Clean(pat)}
	}
	m, _ := filepath.Glob(pat)
	return m
}

// tailError is called by tailers, which already de-duplicate repeated errors.
func (a *Agent) tailError(path string, err error) {
	a.log.Warn("tail error", "file", path, "err", err)
	a.events.add(Event{Time: time.Now(), Type: "error", File: path, Message: err.Error()})
}

func (a *Agent) Rules() *rules.Compiled {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rules
}

func (a *Agent) Events(limit int) []Event { return a.events.list(limit) }

// Active returns the running rule set: the rules plus the local overlay.
func (a *Agent) Active() *rules.Compiled {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.active
}

// TestLine reports which active rules would match line (ignoring files).
func (a *Agent) TestLine(line string) []string {
	var hits []string
	for _, r := range a.Active().Rules {
		if r.Re.MatchString(line) && (r.ExcludeRe == nil || !r.ExcludeRe.MatchString(line)) {
			hits = append(hits, r.Name)
		}
	}
	return hits
}

type Status struct {
	Name          string    `json:"name"`
	Host          string    `json:"host"`
	Version       string    `json:"version"`
	StartedAt     time.Time `json:"started_at"`
	RulesHash     string    `json:"rules_hash"`
	RulesLoadedAt time.Time `json:"rules_loaded_at"`
	RulesOrigin   string    `json:"rules_origin"`
	// Local overlay (this machine's extra rules), if any.
	LocalRulesHash  string       `json:"local_rules_hash,omitempty"`
	LocalRules      int          `json:"local_rules,omitempty"`
	LocalRulesError string       `json:"local_rules_error,omitempty"`
	Rules           []RuleStatus `json:"rules"`
	// OwnRulesHash identifies the agent's own rules saved when a group
	// replaced them (restorable after leaving the group), if any.
	OwnRulesHash string `json:"own_rules_hash,omitempty"`
	// AlertsTotal counts every alert the rules raised since the agent
	// started, across rule changes. The dashboard uses it to spot alert
	// spikes during a staged rollout.
	AlertsTotal uint64       `json:"alerts_total"`
	Files       []FileStatus `json:"files"`
	Webhooks    struct {
		Sent    uint64 `json:"sent"`
		Failed  uint64 `json:"failed"`
		Dropped uint64 `json:"dropped"`
		Queued  int    `json:"queued"`
		// Connected agents: alerts handed to the dashboard, sent directly
		// because it was unreachable, and dropped because it had silenced them.
		ViaDashboard uint64 `json:"via_dashboard"`
		Fallback     uint64 `json:"fallback"`
		Silenced     uint64 `json:"silenced"`
	} `json:"webhooks"`
	SuppressKeys int `json:"suppress_keys"`
	// Kubernetes is set when rules read pod logs.
	Kubernetes *KubeStatus      `json:"kubernetes,omitempty"`
	Dashboard  *DashboardStatus `json:"dashboard,omitempty"`
	Memory     MemoryStats      `json:"memory"`
}

type RuleStatus struct {
	Name     string   `json:"name"`
	Pattern  string   `json:"pattern"`
	Files    []string `json:"files"`
	Suppress string   `json:"suppress,omitempty"`
	Local    bool     `json:"local,omitempty"` // from the local overlay
	// Absence rules: the expected line, how long it may be missing, whether
	// the rule is firing and when the line was last seen.
	Absent       string    `json:"absent,omitempty"`
	For          string    `json:"for,omitempty"`
	Firing       bool      `json:"firing,omitempty"`
	LastSeenLine time.Time `json:"last_seen_line,omitempty"`
	RuleStats
}

type FileStatus struct {
	Path   string   `json:"path"`
	Open   bool     `json:"open"`
	Offset int64    `json:"offset"`
	Lines  uint64   `json:"lines"`
	Rules  []string `json:"rules"`
	Error  string   `json:"error,omitempty"`
}

type MemoryStats struct {
	HeapAlloc   uint64 `json:"heap_alloc"`
	HeapInuse   uint64 `json:"heap_inuse"`
	Sys         uint64 `json:"sys"`
	NumGC       uint32 `json:"num_gc"`
	Goroutines  int    `json:"goroutines"`
	MemoryLimit int64  `json:"memory_limit"`
	// Breakdown of what counts against the memory limit.
	StackInuse   uint64  `json:"stack_inuse"`
	HeapIdle     uint64  `json:"heap_idle"`
	HeapReleased uint64  `json:"heap_released"`
	GCCPU        float64 `json:"gc_cpu_fraction"`
}

func (a *Agent) Status() Status {
	var s Status
	s.Name, s.Host, s.Version, s.StartedAt = a.cfg.Name, a.host, Version, a.started

	stats := a.eng.ruleStats()
	snap := a.eng.snap.Load()

	a.mu.Lock()
	s.RulesHash, s.RulesLoadedAt, s.RulesOrigin = a.rules.Hash, a.rulesLoadedAt, a.rulesOrigin
	if len(bytes.TrimSpace(a.localRaw)) > 0 {
		s.LocalRulesHash, s.LocalRulesError = a.localHash, a.localErr
		if a.localErr == "" {
			s.LocalRules = len(a.active.Rules) - len(a.rules.Rules)
		}
	}
	for i, r := range a.active.Rules {
		rs := RuleStatus{Name: r.Name, Pattern: r.Pattern, Files: r.Files, RuleStats: stats[r.Name], Local: i >= len(a.rules.Rules)}
		if r.Absence {
			rs.Absent, rs.For = r.Absent, r.For.D().String()
			rs.LastSeenLine, rs.Firing = a.eng.absenceInfo(r.Name)
		}
		if w := r.SuppressWindow(); w > 0 {
			rs.Suppress = fmt.Sprintf("%d per %s", r.MaxAlerts(), w)
			if r.Suppress.GroupBy != "" {
				rs.Suppress += " by " + r.Suppress.GroupBy
			}
		}
		s.Rules = append(s.Rules, rs)
	}
	for p, h := range a.tailers {
		fs := FileStatus{Path: p, Open: h.t.opened.Load(), Offset: h.t.offset.Load(), Lines: h.t.lines.Load()}
		if e := h.t.lastErr.Load(); e != nil {
			fs.Error = *e
		}
		for _, r := range snap.byFile[p] {
			fs.Rules = append(fs.Rules, r.Name)
		}
		s.Files = append(s.Files, fs)
	}
	active := a.active
	a.mu.Unlock()
	var kfiles []FileStatus
	s.Kubernetes, kfiles = a.kube.status(active)
	s.Files = append(s.Files, kfiles...)
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Path < s.Files[j].Path })

	s.Webhooks.Sent = a.notif.sender.Sent.Load()
	s.Webhooks.Failed = a.notif.sender.Failed.Load()
	s.Webhooks.Dropped = a.notif.sender.Dropped.Load()
	s.Webhooks.ViaDashboard = a.notif.routed.Load()
	s.Webhooks.Fallback = a.notif.fallback.Load()
	s.Webhooks.Silenced = a.notif.silencedCount.Load()
	s.Webhooks.Queued = a.notif.sender.Queued()
	s.SuppressKeys = a.eng.suppressKeys()
	s.AlertsTotal = a.eng.alertsTotal.Load()
	if raw, ok := a.OwnRules(); ok {
		s.OwnRulesHash = rules.Hash(raw)
	}
	if a.conn != nil {
		ds := a.conn.status()
		s.Dashboard = &ds
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.Memory = MemoryStats{
		HeapAlloc:    ms.HeapAlloc,
		HeapInuse:    ms.HeapInuse,
		Sys:          ms.Sys,
		NumGC:        ms.NumGC,
		Goroutines:   runtime.NumGoroutine(),
		MemoryLimit:  debug.SetMemoryLimit(-1),
		StackInuse:   ms.StackInuse,
		HeapIdle:     ms.HeapIdle,
		HeapReleased: ms.HeapReleased,
		GCCPU:        ms.GCCPUFraction,
	}
	return s
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, data) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rules-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
