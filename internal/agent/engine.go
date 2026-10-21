package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fadhaw/grepalert/internal/alert"
	"github.com/fadhaw/grepalert/internal/rules"
)

// Alert is what gets delivered to a webhook (shared with the dashboard).
type Alert = alert.Alert

// maxSuppressKeys bounds the suppression table. With group_by on a
// high-cardinality capture (e.g. request IDs) the table could otherwise grow
// without limit; past this size new keys share one overflow bucket per rule.
const maxSuppressKeys = 10000

const overflowKey = "\x00overflow"

type suppressKey struct{ rule, group string }

type suppressState struct {
	start      time.Time
	window     time.Duration
	sent       int
	suppressed int
	lastLine   string
	lastFile   string
	rule       *rules.CompiledRule
}

// absentState tracks one absence rule.
type absentState struct {
	lastSeen time.Time
	firing   bool
	rule     *rules.CompiledRule
}

// RuleStats are per-rule counters exposed to the dashboard.
type RuleStats struct {
	Matches    uint64    `json:"matches"`
	Alerts     uint64    `json:"alerts"`
	Suppressed uint64    `json:"suppressed"`
	LastMatch  time.Time `json:"last_match,omitempty"`
}

// engine evaluates lines against the active rule set and applies suppression.
type engine struct {
	agentName, host string
	notify          func(Alert, *rules.CompiledRule)
	events          *ring
	log             *slog.Logger // matches are logged at debug level; nil: not at all

	snap        atomic.Pointer[snapshot]
	alertsTotal atomic.Uint64 // every alert dispatched, across rule changes

	mu       sync.Mutex
	suppress map[suppressKey]*suppressState
	stats    map[string]*RuleStats
	absent   map[string]*absentState

	now func() time.Time
}

// snapshot is an immutable view of the rule set plus the file→rules index.
// Tailers read it lock-free; reloads swap it atomically.
type snapshot struct {
	rules  *rules.Compiled
	byFile map[string][]*rules.CompiledRule
}

func newEngine(agentName, host string, events *ring, notify func(Alert, *rules.CompiledRule)) *engine {
	e := &engine{
		agentName: agentName,
		host:      host,
		notify:    notify,
		events:    events,
		suppress:  map[suppressKey]*suppressState{},
		stats:     map[string]*RuleStats{},
		absent:    map[string]*absentState{},
		now:       time.Now,
	}
	e.snap.Store(&snapshot{rules: &rules.Compiled{}, byFile: map[string][]*rules.CompiledRule{}})
	return e
}

// setSnapshot installs a new rule set and drops state of rules that no longer exist.
func (e *engine) setSnapshot(s *snapshot) {
	old := e.snap.Swap(s)
	if old != nil && old.rules == s.rules {
		return // only the file index changed (glob re-scan)
	}
	live := map[string]*rules.CompiledRule{}
	for _, r := range s.rules.Rules {
		live[r.Name] = r
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, st := range e.suppress {
		r, ok := live[k.rule]
		if !ok {
			delete(e.suppress, k)
			continue
		}
		st.rule = r // keep the window running, but with the new definition
	}
	for name := range e.stats {
		if _, ok := live[name]; !ok {
			delete(e.stats, name)
		}
	}
	// Absence rules: a new rule gets its full "for" duration before it can
	// fire; an existing one keeps its timer across reloads.
	now := e.now()
	for name, st := range e.absent {
		if r, ok := live[name]; ok && r.Absence {
			st.rule = r
		} else {
			delete(e.absent, name)
		}
	}
	for _, r := range s.rules.Rules {
		if r.Absence && e.absent[r.Name] == nil {
			e.absent[r.Name] = &absentState{lastSeen: now, rule: r}
		}
	}
}

// process is called by tailers for every line. It allocates only on a match.
func (e *engine) process(path string, line []byte) {
	s := e.snap.Load()
	for _, r := range s.byFile[path] {
		if r.Pre != nil && !r.Pre.MayMatch(line) {
			continue
		}
		if r.Absence {
			if r.Re.Match(line) && (r.ExcludeRe == nil || !r.ExcludeRe.Match(line)) {
				e.absentSeen(r, path, line)
			}
			continue
		}
		m := r.Re.FindSubmatchIndex(line)
		if m == nil {
			continue
		}
		if r.ExcludeRe != nil && r.ExcludeRe.Match(line) {
			if e.debug() {
				e.log.Debug("rule matched, but the line is excluded", "rule", r.Name, "file", path, "line", debugLine(line))
			}
			continue
		}
		e.match(r, path, line, m)
	}
}

func (e *engine) match(r *rules.CompiledRule, path string, line []byte, m []int) {
	now := e.now()
	group := ""
	if r.GroupIdx > 0 && m[2*r.GroupIdx] >= 0 {
		group = string(line[m[2*r.GroupIdx]:m[2*r.GroupIdx+1]])
	}

	e.mu.Lock()
	st := e.stats[r.Name]
	if st == nil {
		st = &RuleStats{}
		e.stats[r.Name] = st
	}
	st.Matches++
	st.LastMatch = now

	carried := 0
	if win := r.SuppressWindow(); win > 0 {
		key := suppressKey{r.Name, group}
		ss := e.suppress[key]
		if ss == nil && len(e.suppress) >= maxSuppressKeys {
			key.group = overflowKey
			ss = e.suppress[key]
		}
		switch {
		case ss == nil || now.Sub(ss.start) >= win:
			if ss != nil {
				carried = ss.suppressed
			}
			e.suppress[key] = &suppressState{start: now, window: win, sent: 1, rule: r}
		case ss.sent < r.MaxAlerts():
			ss.sent++
		default:
			ss.suppressed++
			ss.lastLine = string(line)
			ss.lastFile = path
			st.Suppressed++
			n := ss.suppressed
			e.mu.Unlock()
			if e.debug() {
				e.log.Debug("rule matched, alert suppressed", "rule", r.Name, "file", path, "line", debugLine(line),
					"groups", captures(r, line, m), "suppressed_in_window", n)
			}
			return
		}
	}
	st.Alerts++
	e.mu.Unlock()
	if e.debug() {
		e.log.Debug("rule matched, sending alert", "rule", r.Name, "file", path, "line", debugLine(line),
			"groups", captures(r, line, m))
	}

	a := e.newAlert(alert.KindMatch, r, path, string(line), now)
	a.GroupKey = group
	a.Suppressed = carried
	a.Groups = captures(r, line, m)
	e.dispatch(a, r)
}

// debug reports whether matches are logged, so the hot path only builds log
// records when they will be written.
func (e *engine) debug() bool {
	return e.log != nil && e.log.Enabled(context.Background(), slog.LevelDebug)
}

// debugLine is a line as logged at debug level: cut at 1 KB.
func debugLine(line []byte) string {
	const max = 1024
	if len(line) > max {
		return string(line[:max]) + "…"
	}
	return string(line)
}

// captures returns the named groups of a match, for webhook templates
// ({{ .Groups.name }}), or nil when the pattern has none.
func captures(r *rules.CompiledRule, line []byte, m []int) map[string]string {
	if len(r.Re.SubexpNames()) <= 1 || m == nil {
		return nil
	}
	out := map[string]string{}
	for i, name := range r.Re.SubexpNames() {
		if name != "" && m[2*i] >= 0 {
			out[name] = string(line[m[2*i]:m[2*i+1]])
		}
	}
	return out
}

// sweep closes expired suppression windows, emitting summary alerts for windows
// that swallowed matches, and frees their state.
func (e *engine) sweep() {
	now := e.now()
	var summaries []Alert
	var rs []*rules.CompiledRule

	e.mu.Lock()
	for k, ss := range e.suppress {
		if now.Sub(ss.start) < ss.window {
			continue
		}
		delete(e.suppress, k)
		if ss.suppressed > 0 && ss.rule.SendSummary() {
			a := e.newAlert(alert.KindSummary, ss.rule, ss.lastFile, ss.lastLine, now)
			a.GroupKey = k.group
			a.Suppressed = ss.suppressed
			// Templates can use the same captured values as for the match.
			a.Groups = captures(ss.rule, []byte(ss.lastLine), ss.rule.Re.FindStringSubmatchIndex(ss.lastLine))
			summaries = append(summaries, a)
			rs = append(rs, ss.rule)
		}
	}
	// Absence rules whose line has not been seen for their duration fire once.
	for _, st := range e.absent {
		if st.firing || now.Sub(st.lastSeen) < st.rule.For.D() {
			continue
		}
		st.firing = true
		r := st.rule
		a := e.newAlert(alert.KindAbsent, r, strings.Join(r.Files, ", "),
			fmt.Sprintf("%s for %s (expected %q)", strings.Join(r.Files, ", "), r.For.D(), r.Absent), now)
		summaries = append(summaries, a)
		rs = append(rs, r)
		e.statsFor(r.Name).Alerts++
	}
	e.mu.Unlock()

	for i := range summaries {
		e.dispatch(summaries[i], rs[i])
	}
}

// absentSeen records a line matching an absence rule, and sends a recovery
// alert if the rule was firing.
func (e *engine) absentSeen(r *rules.CompiledRule, path string, line []byte) {
	now := e.now()
	e.mu.Lock()
	st := e.statsFor(r.Name)
	st.Matches++
	st.LastMatch = now
	as := e.absent[r.Name]
	recovered := as != nil && as.firing
	if as != nil {
		as.lastSeen, as.firing = now, false
	}
	e.mu.Unlock()
	if recovered {
		e.dispatch(e.newAlert(alert.KindRecovered, r, path, string(line), now), r)
	}
}

// statsFor returns the stats entry of a rule; callers hold e.mu.
func (e *engine) statsFor(name string) *RuleStats {
	st := e.stats[name]
	if st == nil {
		st = &RuleStats{}
		e.stats[name] = st
	}
	return st
}

// absenceInfo reports an absence rule's state for the status page.
func (e *engine) absenceInfo(name string) (lastSeen time.Time, firing bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if st := e.absent[name]; st != nil {
		return st.lastSeen, st.firing
	}
	return time.Time{}, false
}

func (e *engine) newAlert(kind string, r *rules.CompiledRule, path, line string, now time.Time) Alert {
	return Alert{
		Kind:        kind,
		Agent:       e.agentName,
		Host:        e.host,
		Rule:        r.Name,
		Description: r.Description,
		Severity:    r.Severity,
		Labels:      r.Labels,
		File:        path,
		Line:        line,
		Time:        now,
	}
}

func (e *engine) dispatch(a Alert, r *rules.CompiledRule) {
	e.alertsTotal.Add(1)
	a.Text = alert.FormatText(a)
	e.events.add(Event{Time: a.Time, Type: "alert", Rule: a.Rule, File: a.File, Message: a.Text})
	e.notify(a, r)
}

func (e *engine) ruleStats() map[string]RuleStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]RuleStats, len(e.stats))
	for k, v := range e.stats {
		out[k] = *v
	}
	return out
}

func (e *engine) suppressKeys() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.suppress)
}
