package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fadhaw/grepalert/internal/alert"
	"github.com/fadhaw/grepalert/internal/rules"
)

// Connected agents hand their alerts to the dashboard, which:
//   - drops alerts covered by an active silence (recording them in history),
//   - deduplicates the same alert across a group's agents: the first one
//     waits FleetSettings.Wait to gather other hosts, is sent once ("on 50
//     hosts"), and repeats are held back for FleetSettings.Window, after
//     which a summary is sent if anything was held back,
//   - delivers to the webhooks the agent resolved, and
//   - sends agent-down/up alerts to the ops webhook.
// Agents deliver directly when they cannot reach the dashboard.

const (
	historySize  = 1000
	maxListHosts = 10 // hosts named in a fleet alert; the rest are counted
)

// HistoryEntry is one alert the dashboard handled.
type HistoryEntry struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Group     string    `json:"group,omitempty"`
	Rule      string    `json:"rule"`
	GroupKey  string    `json:"group_key,omitempty"`
	Hosts     []string  `json:"hosts,omitempty"`
	HostCount int       `json:"host_count"`
	// Status: sent, failed, silenced, dropped or no destination.
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Text    string `json:"text"`
	Silence string `json:"silence,omitempty"`
}

type fleet struct {
	s      *Server
	sender *alert.Sender

	mu       sync.Mutex
	buckets  map[string]*bucket
	history  []*HistoryEntry // ring, newest at (next-1)
	next     int
	silenced map[string]bool // silence|rule|key already recorded in history
	down     map[string]*downState
	started  time.Time

	now func() time.Time
}

type bucket struct {
	group     string
	first     alert.Alert
	hooks     []*alert.Hook
	hosts     []string
	hostSet   map[string]bool
	matches   int
	sendAt    time.Time // end of the gathering period
	sent      bool
	windowEnd time.Time
	// held back during the window
	supCount int
	supHosts []string
	supSet   map[string]bool
	lastLine string
}

type downState struct {
	offlineSince time.Time
	notified     bool
	group        string
}

func newFleet(s *Server) *fleet {
	f := &fleet{
		s:        s,
		sender:   alert.NewSender(2000, 2, "grepalert-dashboard"),
		buckets:  map[string]*bucket{},
		history:  make([]*HistoryEntry, historySize),
		silenced: map[string]bool{},
		down:     map[string]*downState{},
		started:  time.Now(),
		now:      time.Now,
	}
	f.sender.OnResult = f.recordResult
	return f
}

// Run delivers and sweeps until ctx is done.
func (f *fleet) Run(ctx context.Context) {
	f.sender.Start(ctx, 4)
	// The agent-down check calls direct agents (with timeouts), so it runs on
	// its own goroutine: it must never delay closing fleet windows.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				f.checkAgents(ctx)
			}
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			f.flushAll()
			f.sender.Wait()
			return
		case <-tick.C:
			f.sweep()
		}
	}
}

// ---- history ----

func (f *fleet) record(e *HistoryEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordLocked(e)
}

func (f *fleet) recordLocked(e *HistoryEntry) {
	if e.ID == "" {
		e.ID = randomID()
	}
	f.history[f.next] = e
	f.next = (f.next + 1) % len(f.history)
}

func (f *fleet) recordResult(a alert.Alert, r alert.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.history {
		if e == nil || e.ID != a.ID {
			continue
		}
		if r.Err != nil {
			e.Status = "failed"
			e.Detail = strings.TrimSpace(e.Detail + fmt.Sprintf(" %s: %v", r.Hook, r.Err))
		}
		return
	}
}

// History returns up to limit entries, newest first, optionally for one group.
func (f *fleet) History(group string, limit int) []HistoryEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []HistoryEntry{}
	for i := 0; i < len(f.history) && len(out) < limit; i++ {
		e := f.history[(f.next-1-i+len(f.history))%len(f.history)]
		if e == nil {
			break
		}
		if group == "" || e.Group == group {
			out = append(out, *e)
		}
	}
	return out
}

// ---- intake ----

func (f *fleet) ingest(a alert.Alert, hooks []*alert.Hook, groupRec *GroupRecord) {
	now := f.now()
	a.Via = "dashboard"
	if sl, ok := f.s.store.activeSilence(a.Group, a.Agent, a.Rule); ok {
		f.mu.Lock()
		key := sl.ID + "|" + a.Rule + "|" + a.GroupKey
		if !f.silenced[key] { // one history entry per silence, rule and key
			f.silenced[key] = true
			a.Text = alert.FormatText(a)
			f.recordLocked(&HistoryEntry{Time: now, Kind: a.Kind, Group: a.Group, Rule: a.Rule, GroupKey: a.GroupKey,
				Hosts: []string{a.Agent}, HostCount: 1, Status: "silenced", Silence: sl.ID, Text: a.Text,
				Detail: "further matches covered by this silence are not listed"})
		}
		f.mu.Unlock()
		return
	}
	if groupRec == nil || groupRec.Fleet.Disabled || a.Kind == alert.KindRecovered {
		a.Hosts, a.HostCount = []string{a.Agent}, 1
		f.emit(a, hooks)
		return
	}

	key := strings.Join([]string{a.Kind, a.Group, a.Rule, a.GroupKey}, "\x00")
	if a.Kind == alert.KindSummary {
		// An agent's own suppression summary: fold it into the fleet window.
		key = strings.Join([]string{alert.KindMatch, a.Group, a.Rule, a.GroupKey}, "\x00")
	}
	f.mu.Lock()
	b := f.buckets[key]
	switch {
	case b == nil && a.Kind == alert.KindSummary:
		f.mu.Unlock()
		a.Hosts, a.HostCount = []string{a.Agent}, 1
		f.emit(a, hooks) // no fleet window open: pass it on
		return
	case b == nil:
		b = &bucket{group: a.Group, first: a, hooks: hooks, hostSet: map[string]bool{}, supSet: map[string]bool{},
			sendAt: now.Add(groupRec.Fleet.waitD())}
		f.buckets[key] = b
		fallthrough
	case !b.sent:
		b.matches++
		if !b.hostSet[a.Agent] {
			b.hostSet[a.Agent] = true
			b.hosts = append(b.hosts, a.Agent)
		}
	default: // already sent: hold back until the window closes
		n := 1
		if a.Kind == alert.KindSummary {
			n = a.Suppressed
		}
		b.supCount += n
		b.lastLine = a.Line
		if !b.supSet[a.Agent] {
			b.supSet[a.Agent] = true
			b.supHosts = append(b.supHosts, a.Agent)
		}
	}
	f.mu.Unlock()
	if groupRec.Fleet.waitD() == 0 {
		f.sweep()
	}
}

// sweep sends gathered alerts whose wait is over and closes fleet windows.
// sweepSlack lets a sweep also handle deadlines that fall just after it: the
// sweep runs every second, in step with when windows start, so without it
// every window would close one tick (about a second) late.
const sweepSlack = 50 * time.Millisecond

func (f *fleet) sweep() {
	now := f.now()
	due := now.Add(sweepSlack)
	type out struct {
		a     alert.Alert
		hooks []*alert.Hook
	}
	var send []out
	f.mu.Lock()
	for key, b := range f.buckets {
		switch {
		case !b.sent && !due.Before(b.sendAt):
			a := b.first
			a.HostCount = len(b.hosts)
			a.Hosts = b.hosts[:min(len(b.hosts), maxListHosts)]
			a.Suppressed += b.matches - len(b.hosts) // repeats from the same hosts
			send = append(send, out{a, b.hooks})
			b.sent = true
			b.windowEnd = now.Add(f.windowFor(b.group))
		case b.sent && !due.Before(b.windowEnd):
			delete(f.buckets, key)
			f.s.log.Info("fleet window closed", "group", b.group, "rule", b.first.Rule, "key", b.first.GroupKey,
				"held_back", b.supCount, "hosts", len(b.supHosts), "late", now.Sub(b.windowEnd).Round(time.Millisecond))
			if b.supCount > 0 {
				a := b.first
				a.Kind = alert.KindFleetSummary
				a.Suppressed, a.HostCount = b.supCount, len(b.supHosts)
				a.Hosts = b.supHosts[:min(len(b.supHosts), maxListHosts)]
				a.Line, a.Time = b.lastLine, now
				send = append(send, out{a, b.hooks})
			}
		}
	}
	f.mu.Unlock()
	for _, o := range send {
		f.emit(o.a, o.hooks)
	}
}

func (f *fleet) windowFor(group string) time.Duration {
	if g, ok := f.s.store.Group(group); ok {
		return g.Fleet.windowD()
	}
	return defaultFleetWindow
}

// flushAll sends everything still gathering (used at shutdown).
func (f *fleet) flushAll() {
	f.mu.Lock()
	for _, b := range f.buckets {
		b.sendAt = time.Time{}
	}
	f.mu.Unlock()
	f.sweep()
}

// emit records an alert and queues it to its webhooks.
func (f *fleet) emit(a alert.Alert, hooks []*alert.Hook) {
	a.ID = randomID()
	if a.HostCount == 0 {
		a.Hosts, a.HostCount = []string{a.Agent}, 1
	}
	a.Text = alert.FormatText(a)
	// A silence may have started while this alert was gathering hosts or its
	// window was open: check again right before sending.
	agent := a.Agent
	if a.HostCount > 1 {
		agent = "" // several hosts: only silences without an agent filter apply
	}
	if sl, ok := f.s.store.activeSilence(a.Group, agent, a.Rule); ok {
		f.record(&HistoryEntry{ID: a.ID, Time: f.now(), Kind: a.Kind, Group: a.Group, Rule: a.Rule, GroupKey: a.GroupKey,
			Hosts: a.Hosts, HostCount: a.HostCount, Status: "silenced", Silence: sl.ID, Text: a.Text})
		return
	}
	e := &HistoryEntry{ID: a.ID, Time: f.now(), Kind: a.Kind, Group: a.Group, Rule: a.Rule, GroupKey: a.GroupKey,
		Hosts: a.Hosts, HostCount: a.HostCount, Status: "sent", Text: a.Text}
	if len(hooks) == 0 {
		e.Status = "no destination"
	}
	f.record(e)
	for _, h := range hooks {
		if !f.sender.Enqueue(a, h) {
			f.mu.Lock()
			e.Status, e.Detail = "dropped", "delivery queue full"
			f.mu.Unlock()
		}
	}
}

// ---- agent down/up ----

// checkAgents sends agent-down alerts for agents unreachable for longer than
// the configured delay, and agent-up alerts when they come back.
func (f *fleet) checkAgents(ctx context.Context) {
	settings := f.s.store.Settings()
	after := settings.agentDownAfter()
	groups := f.s.store.Groups()
	agents := f.s.store.Agents()
	online := make([]bool, len(agents))

	var wg sync.WaitGroup
	for i, a := range agents {
		if a.Revoked {
			continue
		}
		if a.Connected() {
			online[i] = f.s.tunnelFor(a.ID).online()
			continue
		}
		wg.Add(1)
		go func(i int, a AgentRecord) { // direct agents: ask them
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			_, err := f.s.client(a).status(cctx)
			online[i] = err == nil
		}(i, a)
	}
	wg.Wait()

	now := f.now()
	seen := map[string]bool{}
	type ev struct {
		kind, agent, group, detail string
	}
	var events []ev
	f.mu.Lock()
	for i, a := range agents {
		if a.Revoked {
			continue
		}
		seen[a.Name] = true
		st := f.down[a.Name]
		if st == nil {
			st = &downState{}
			f.down[a.Name] = st
		}
		st.group = EffectiveGroup(a, groups)
		if online[i] {
			if st.notified {
				events = append(events, ev{alert.KindAgentUp, a.Name, st.group,
					fmt.Sprintf("reachable again after %s", now.Sub(st.offlineSince).Round(time.Second))})
			}
			st.offlineSince, st.notified = time.Time{}, false
			continue
		}
		if st.offlineSince.IsZero() {
			st.offlineSince = now
			if a.Connected() {
				// Never seen since the dashboard started: count from its start.
				if seenAt := f.s.lastSeenAt(a.ID); !seenAt.IsZero() {
					st.offlineSince = seenAt
				} else {
					st.offlineSince = f.started
				}
			}
		}
		if !st.notified && now.Sub(st.offlineSince) >= after {
			st.notified = true
			events = append(events, ev{alert.KindAgentDown, a.Name, st.group,
				fmt.Sprintf("unreachable since %s (%s)", st.offlineSince.Format(time.RFC3339), now.Sub(st.offlineSince).Round(time.Second))})
		}
	}
	for name := range f.down {
		if !seen[name] {
			delete(f.down, name) // removed or revoked: no more alerts
		}
	}
	f.mu.Unlock()

	for _, e := range events {
		f.agentEvent(e.kind, e.agent, e.group, e.detail, settings)
	}
}

func (f *fleet) agentEvent(kind, agent, group, detail string, settings Settings) {
	a := alert.Alert{Kind: kind, Agent: agent, Host: agent, Group: group, Rule: AgentDownRule,
		Severity: "critical", Line: detail, Time: f.now(), Via: "dashboard"}
	if kind == alert.KindAgentUp {
		a.Severity = "info"
	}
	if sl, ok := f.s.store.activeSilence(group, agent, AgentDownRule); ok {
		a.Text = alert.FormatText(a)
		f.record(&HistoryEntry{Time: a.Time, Kind: kind, Group: group, Rule: AgentDownRule, Hosts: []string{agent},
			HostCount: 1, Status: "silenced", Silence: sl.ID, Text: a.Text})
		return
	}
	var hooks []*alert.Hook
	if h := f.opsHook(group, settings); h != nil {
		hooks = []*alert.Hook{h}
	}
	f.emit(a, hooks)
}

// opsHook is where agent-down/up alerts go: the group's URL, else the
// dashboard-wide ops webhook.
func (f *fleet) opsHook(group string, settings Settings) *alert.Hook {
	url := settings.OpsWebhook.URL
	if g, ok := f.s.store.Group(group); ok && g.OpsWebhookURL != "" {
		url = g.OpsWebhookURL
	}
	if url = rules.ExpandEnv(url); url == "" {
		return nil
	}
	h := &alert.Hook{Name: "ops", URL: url, Template: settings.OpsWebhook.Template}
	if err := h.Compile(); err != nil {
		f.s.log.Error("ops webhook template", "err", err)
		h = &alert.Hook{Name: "ops", URL: url}
		h.Compile()
	}
	return h
}

// downStates reports agents currently considered down, for the overview.
func (f *fleet) downStates() map[string]time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]time.Time{}
	for name, st := range f.down {
		if st.notified {
			out[name] = st.offlineSince
		}
	}
	return out
}

// ---- HTTP ----

// handleAlerts receives alerts from a connected agent.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	a, ok := s.agentAuth(w, r)
	if !ok {
		return
	}
	var body struct {
		Alerts []struct {
			Alert alert.Alert   `json:"alert"`
			Hooks []*alert.Hook `json:"hooks"`
		} `json:"alerts"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8*maxProxyBody)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.tunnelFor(a.ID).seen()
	groupName := EffectiveGroup(a, s.store.Groups())
	var group *GroupRecord
	if g, ok := s.store.Group(groupName); ok {
		group = &g
	}
	for _, ra := range body.Alerts {
		hooks := ra.Hooks[:0]
		for _, h := range ra.Hooks {
			if h != nil && h.Compile() == nil {
				hooks = append(hooks, h)
			}
		}
		al := ra.Alert
		al.Agent, al.Group = a.Name, groupName // trust the credential, not the payload
		s.fleet.ingest(al, hooks, group)
	}
	w.WriteHeader(http.StatusNoContent)
}

// silencesFor returns the active silences that apply to an agent, sent with
// each poll so the agent honours them when it has to deliver directly.
func (s *Server) silencesFor(a AgentRecord) []map[string]any {
	group := EffectiveGroup(a, s.store.Groups())
	now := time.Now()
	out := []map[string]any{}
	for _, sl := range s.store.Silences() {
		if !sl.Active(now) || (sl.Group != "" && sl.Group != group) || (len(sl.Agents) > 0 && !contains(sl.Agents, a.Name)) {
			continue
		}
		out = append(out, map[string]any{"id": sl.ID, "rules": sl.Rules, "ends_at": sl.EndsAt})
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	limit := 300
	fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
	perms := authOf(r).perms
	out := []HistoryEntry{}
	for _, e := range s.fleet.History(r.URL.Query().Get("group"), historySize) {
		if len(out) < min(max(limit, 1), historySize) && perms.Can(RoleViewer, e.Group) {
			out = append(out, e)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListSilences(w http.ResponseWriter, r *http.Request) {
	perms := authOf(r).perms
	list := []Silence{}
	for _, sl := range s.store.Silences() {
		if perms.Can(RoleViewer, sl.Group) {
			list = append(list, sl)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].EndsAt.After(list[j].EndsAt) })
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleAddSilence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group    string   `json:"group"`
		Agents   []string `json:"agents"`
		Rules    []string `json:"rules"`
		Duration string   `json:"duration"` // e.g. "2h"
		Reason   string   `json:"reason"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	d, err := time.ParseDuration(req.Duration)
	if err != nil || d <= 0 || d > 30*24*time.Hour {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("duration must be between 1m and 30 days, e.g. 2h"))
		return
	}
	if !s.need(w, r, RoleEditor, req.Group) {
		return
	}
	now := time.Now()
	sl, err := s.store.AddSilence(Silence{Group: req.Group, Agents: clean(req.Agents), Rules: clean(req.Rules),
		StartsAt: now, EndsAt: now.Add(d), Reason: strings.TrimSpace(req.Reason)})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.log.Info("silence created", "id", sl.ID, "group", sl.Group, "rules", sl.Rules, "agents", sl.Agents, "until", sl.EndsAt, "reason", sl.Reason)
	s.audit.record(r, "silence.create", sl.ID, sl.Group, "ok", fmt.Sprintf("until %s; rules %v; agents %v; reason: %s", sl.EndsAt.Format(time.RFC3339), sl.Rules, sl.Agents, sl.Reason), "")
	writeJSON(w, http.StatusOK, sl)
}

func clean(list []string) []string {
	var out []string
	for _, v := range list {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) handleExpireSilence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var target *Silence
	for _, sl := range s.store.Silences() {
		if sl.ID == id {
			target = &sl
		}
	}
	if target == nil {
		writeErr(w, http.StatusNotFound, fmt.Errorf("silence not found"))
		return
	}
	if !s.need(w, r, RoleEditor, target.Group) {
		return
	}
	if err := s.store.ExpireSilence(id); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	s.audit.record(r, "silence.end", id, target.Group, "ok", "reason was: "+target.Reason, "")
	writeJSON(w, http.StatusOK, map[string]string{"expired": r.PathValue("id")})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Settings())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var st Settings
	if !readJSON(w, r, &st) {
		return
	}
	if st.OpsWebhook.Template != "" {
		h := &alert.Hook{Name: "ops", Template: st.OpsWebhook.Template}
		if err := h.Compile(); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	before := s.store.Settings()
	if err := s.store.SetSettings(st); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.audit.record(r, "settings.update", "settings", "", "ok", "", lineDiff(settingsText(before), settingsText(st)))
	writeJSON(w, http.StatusOK, st)
}

// handleTestOps sends a test alert to the ops webhook (of a group, if given).
func (s *Server) handleTestOps(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get("group")
	h := s.fleet.opsHook(group, s.store.Settings())
	if h == nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("no ops webhook configured"))
		return
	}
	a := alert.Alert{ID: randomID(), Kind: alert.KindAgentDown, Agent: "test-agent", Host: "test-agent", Group: group,
		Rule: AgentDownRule, Severity: "info", Line: "this is a test from the grepalert dashboard", Time: time.Now(), Via: "dashboard"}
	a.Text = alert.FormatText(a)
	body, ctype, err := alert.Render(a, h)
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, h.Method, h.URL, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", ctype)
		var resp *http.Response
		if resp, err = http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 300 {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	s.audit.record(r, "settings.test_ops", maskURL(h.URL), group, "ok", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"sent": h.URL})
}

func settingsText(st Settings) string {
	return fmt.Sprintf("ops webhook: %s\nops template: %s\nagent-down after: %s\n",
		maskURL(st.OpsWebhook.URL), orNone(st.OpsWebhook.Template), orNone(st.AgentDownAfter))
}
