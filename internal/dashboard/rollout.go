package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fadhaw/grepalert/internal/alert"
)

// A staged rollout sends a group's new rules to a few agents first (the
// canaries), waits, compares how many alerts they raise with the agents
// still on the previous (stable) version, and only then moves on to more
// agents: by default 1 agent, then 10%, then all. If the canaries reject the
// rules or their alert rate spikes, the rollout halts and every agent goes
// back to the stable version.

// RolloutSettings configure staged rollouts for a group.
type RolloutSettings struct {
	Enabled bool `json:"enabled"`
	// Stages are agent counts ("1", "3") or percentages ("10%"); the last
	// stage is always everyone. Default: 1, 10%, 100%.
	Stages []string `json:"stages,omitempty"`
	// Soak is how long each stage runs before it is judged. Default 5m.
	Soak string `json:"soak,omitempty"`
	// MaxIncrease halts the rollout when canaries raise more than this many
	// times the alerts per agent of the stable agents. Default 3.
	MaxIncrease float64 `json:"max_increase,omitempty"`
	// MinAlerts is the noise floor: fewer canary alerts than this in a stage
	// never count as a spike. Default 10.
	MinAlerts int `json:"min_alerts,omitempty"`
}

var defaultStages = []string{"1", "10%", "100%"}

func (rs *RolloutSettings) validate() error {
	if !rs.Enabled && len(rs.Stages) == 0 && rs.Soak == "" {
		return nil
	}
	var stages []string
	for _, st := range rs.Stages {
		if st = strings.TrimSpace(st); st != "" {
			stages = append(stages, st)
		}
	}
	if len(stages) == 0 {
		stages = append([]string(nil), defaultStages...)
	}
	for _, st := range stages {
		if _, _, err := parseStage(st); err != nil {
			return err
		}
	}
	if last := stages[len(stages)-1]; last != "100%" {
		stages = append(stages, "100%")
	}
	if len(stages) > 10 {
		return errors.New("at most 10 stages")
	}
	rs.Stages = stages
	if rs.Soak == "" {
		rs.Soak = "5m"
	}
	if d, err := time.ParseDuration(rs.Soak); err != nil || d < 10*time.Second || d > 24*time.Hour {
		return errors.New("soak must be a duration between 10s and 24h, e.g. 5m")
	}
	if rs.MaxIncrease == 0 {
		rs.MaxIncrease = 3
	}
	if rs.MaxIncrease < 1 {
		return errors.New("max_increase must be at least 1")
	}
	if rs.MinAlerts == 0 {
		rs.MinAlerts = 10
	}
	if rs.MinAlerts < 0 {
		return errors.New("min_alerts must not be negative")
	}
	return nil
}

// stages returns the configured stages, or the defaults.
func (rs RolloutSettings) stages() []string {
	if len(rs.Stages) == 0 {
		return defaultStages
	}
	return rs.Stages
}

func (rs RolloutSettings) soak() time.Duration {
	d, _ := time.ParseDuration(rs.Soak)
	if d <= 0 {
		d = 5 * time.Minute
	}
	return d
}

func parseStage(st string) (n int, percent bool, err error) {
	s := strings.TrimSuffix(st, "%")
	percent = s != st
	n, err = strconv.Atoi(s)
	if err != nil || n < 1 || (percent && n > 100) {
		return 0, false, fmt.Errorf("invalid stage %q: use an agent count like 1 or a percentage like 10%%", st)
	}
	return n, percent, nil
}

// stageSize is how many of total agents a stage covers (at least one).
func stageSize(st string, total int) int {
	n, percent, err := parseStage(st)
	if err != nil {
		return total
	}
	if percent {
		n = int(math.Ceil(float64(total) * float64(n) / 100))
	}
	return max(1, min(n, total))
}

// Rollout is the state of one staged rollout.
type Rollout struct {
	ID         string `json:"id"`
	Hash       string `json:"hash"`        // version being rolled out
	StableHash string `json:"stable_hash"` // version everyone else keeps
	Stage      int    `json:"stage"`       // index into the group's stages
	// Status is running, halted (canaries went back to stable; retry or
	// abort), done (everyone runs Hash) or aborted (everyone back on stable).
	Status       string    `json:"status"`
	Reason       string    `json:"reason,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	StartedBy    string    `json:"started_by,omitempty"`
	StageStarted time.Time `json:"stage_started"`
	UpdatedAt    time.Time `json:"updated_at"`
	// BaselineRate is the stable agents' alerts per agent per minute in the
	// last stage that had any, used when no stable agents are left to
	// compare with.
	BaselineRate *float64      `json:"baseline_rate,omitempty"`
	Log          []RolloutNote `json:"log,omitempty"`
}

type RolloutNote struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

// active reports whether agents may still run different versions.
func (ro *Rollout) active() bool { return ro.Status == "running" || ro.Status == "halted" }

func (ro *Rollout) note(msg string) {
	now := time.Now()
	ro.UpdatedAt = now
	ro.Log = append(ro.Log, RolloutNote{Time: now, Message: msg})
	if len(ro.Log) > 30 {
		ro.Log = ro.Log[len(ro.Log)-30:]
	}
}

func (ro *Rollout) finish(status, reason string) {
	ro.Status, ro.Reason = status, reason
	ro.note(status + ": " + reason)
}

// canaries returns the members that run the new version in the current
// stage. The order is a hash of rollout ID and agent name, so it is stable
// for a rollout, differs between rollouts, and new members land anywhere.
func canaries(ro *Rollout, stages []string, members []AgentRecord) map[string]bool {
	names := make([]string, len(members))
	for i, a := range members {
		names[i] = a.Name
	}
	key := func(n string) string {
		sum := sha256.Sum256([]byte(ro.ID + "/" + n))
		return string(sum[:])
	}
	sort.Slice(names, func(i, j int) bool { return key(names[i]) < key(names[j]) })
	n := stageSize(stages[min(ro.Stage, len(stages)-1)], len(names))
	out := make(map[string]bool, n)
	for _, name := range names[:n] {
		out[name] = true
	}
	return out
}

// targetFor returns the rules an agent of group g should run right now.
func (s *Server) targetFor(g GroupRecord, a AgentRecord, members []AgentRecord) (raw []byte, hash string) {
	ro := g.RolloutState
	if ro == nil || !ro.active() || ro.Hash != g.RulesHash {
		return []byte(g.Rules), g.RulesHash
	}
	stable, ok := s.store.Version(g.Name, ro.StableHash)
	if !ok {
		return []byte(g.Rules), g.RulesHash
	}
	if ro.Status == "running" && canaries(ro, g.Rollout.stages(), members)[a.Name] {
		return []byte(g.Rules), g.RulesHash
	}
	return []byte(stable.Rules), stable.Hash
}

// rolloutOnChange is applied (inside the rules save) when a group's rules
// change from prev to g.RulesHash by an edit or git sync: it starts a staged
// rollout, or replaces a running one.
func rolloutOnChange(g *GroupRecord, prev, actor string) {
	ro := g.RolloutState
	if !g.Rollout.Enabled || prev == "" {
		if ro != nil && ro.active() {
			ro.finish("done", "superseded by "+g.RulesHash+", which went to every agent at once")
		}
		return
	}
	stable := prev
	if ro != nil && ro.active() {
		stable = ro.StableHash // the unfinished version never became stable
		ro.finish("aborted", "superseded by "+g.RulesHash)
	}
	if g.RulesHash == stable {
		return // back to what everyone runs; nothing to roll out
	}
	now := time.Now()
	nr := &Rollout{ID: randomID(), Hash: g.RulesHash, StableHash: stable, Status: "running",
		StartedAt: now, StartedBy: actor, StageStarted: now}
	nr.note(fmt.Sprintf("started: %s → %s, stage 1 of %d (%s)", stable, g.RulesHash, len(g.Rollout.stages()), stageLabel(g.Rollout.stages(), 0)))
	g.RolloutState = nr
}

func stageLabel(stages []string, i int) string {
	st := stages[min(i, len(stages)-1)]
	if strings.HasSuffix(st, "%") {
		return st + " of agents"
	}
	if st == "1" {
		return "1 agent"
	}
	return st + " agents"
}

// rolloutSample is the alert counters of a group's agents at the start of
// a stage's soak (memory only: after a dashboard restart the soak starts over).
type rolloutSample struct {
	key    string // rollout ID and stage
	at     time.Time
	counts map[string]agentCount
}

type agentCount struct {
	alerts uint64
	hash   string
}

// fetchCounts reads every member's alert counter and running rules version.
func (s *Server) fetchCounts(ctx context.Context, members []AgentRecord) map[string]agentCount {
	out := map[string]agentCount{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, a := range members {
		wg.Add(1)
		go func(a AgentRecord) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			raw, err := s.client(a).status(ctx)
			if err != nil {
				return
			}
			var st struct {
				AlertsTotal *uint64 `json:"alerts_total"`
				RulesHash   string  `json:"rules_hash"`
			}
			if json.Unmarshal(raw, &st) != nil || st.AlertsTotal == nil {
				return // an older agent without the counter: not measured
			}
			mu.Lock()
			out[a.Name] = agentCount{*st.AlertsTotal, st.RulesHash}
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	return out
}

// advanceRollouts judges the running rollouts whose stage has soaked long
// enough. It runs on every reconcile tick.
func (s *Server) advanceRollouts(ctx context.Context) {
	for _, g := range s.store.Groups() {
		if ro := g.RolloutState; ro != nil && ro.Status == "running" {
			s.evaluateRollout(ctx, g.Name)
		}
	}
}

func (s *Server) evaluateRollout(ctx context.Context, name string) {
	g, ok := s.store.Group(name)
	if !ok || g.RolloutState == nil || g.RolloutState.Status != "running" {
		return
	}
	ro := g.RolloutState
	members := s.store.Members(name)
	can := canaries(ro, g.Rollout.stages(), members)
	st := s.state(name)

	// Canaries that refused the new rules (not merely offline) stop it at once.
	s.stMu.Lock()
	var rejected []string
	for agent := range can {
		if res, ok := st.Results[agent]; ok && res.Hash == ro.Hash && res.Action == "failed" && !strings.HasPrefix(res.Error, "agent unreachable") {
			rejected = append(rejected, agent+": "+res.Error)
		}
	}
	sample := st.sample
	s.stMu.Unlock()
	if len(rejected) > 0 {
		sort.Strings(rejected)
		s.haltRollout(ctx, name, ro.ID, "the new rules failed to apply on "+strings.Join(rejected, "; "))
		return
	}

	key := fmt.Sprintf("%s/%d", ro.ID, ro.Stage)
	if sample == nil || sample.key != key {
		counts := s.fetchCounts(ctx, members)
		s.stMu.Lock()
		st.sample = &rolloutSample{key: key, at: time.Now(), counts: counts}
		s.stMu.Unlock()
		return
	}
	elapsed := time.Since(sample.at)
	if elapsed < g.Rollout.soak() {
		return
	}

	now := s.fetchCounts(ctx, members)
	minutes := elapsed.Minutes()
	var canAlerts, stAlerts uint64
	var nCan, nSt int
	for agent, before := range sample.counts {
		after, ok := now[agent]
		if !ok || after.alerts < before.alerts { // offline, or restarted (counter reset)
			continue
		}
		d := after.alerts - before.alerts
		switch {
		case can[agent] && after.hash == ro.Hash:
			canAlerts += d
			nCan++
		case !can[agent] && after.hash == ro.StableHash:
			stAlerts += d
			nSt++
		}
	}

	var baseline *float64
	if nSt > 0 {
		b := float64(stAlerts) / float64(nSt) / minutes
		baseline = &b
	} else {
		baseline = ro.BaselineRate
	}
	verdict := fmt.Sprintf("%s raised %d alerts in %s", plural(nCan, "agent on the new version", "agents on the new version"), canAlerts, elapsed.Round(time.Second))
	if nCan > 0 && baseline != nil && canAlerts >= uint64(g.Rollout.MinAlerts) {
		rate := float64(canAlerts) / float64(nCan) / minutes
		if rate > g.Rollout.MaxIncrease**baseline {
			s.haltRollout(ctx, name, ro.ID, fmt.Sprintf("alert spike: the new version raised %.2f alerts per agent per minute, the previous one %.2f (limit %g×); %s",
				rate, *baseline, g.Rollout.MaxIncrease, verdict))
			return
		}
	}
	if nSt > 0 {
		verdict += fmt.Sprintf(" (the others: %.2f per agent per minute)", *baseline)
	} else if baseline != nil {
		verdict += fmt.Sprintf(" (the previous version ran at %.2f per agent per minute in the stage before)", *baseline)
	} else {
		verdict += " (no stable agents to compare with)"
	}

	var promoted bool
	g, err := s.store.MutateGroup(name, func(g *GroupRecord) error {
		ro := g.RolloutState
		if ro == nil || ro.Status != "running" || fmt.Sprintf("%s/%d", ro.ID, ro.Stage) != key {
			return errors.New("rollout changed meanwhile")
		}
		if nSt > 0 {
			ro.BaselineRate = baseline
		}
		promoted = advanceStage(ro, g.Rollout.stages(), verdict)
		return nil
	})
	if err != nil {
		return
	}
	s.log.Info("rollout advanced", "group", name, "stage", g.RolloutState.Stage, "status", g.RolloutState.Status)
	s.audit.system("rollout", "rollout", "group.rollout."+map[bool]string{true: "promote", false: "done"}[promoted], name, name,
		g.RolloutState.Log[len(g.RolloutState.Log)-1].Message, "")
	s.syncGroup(ctx, name, "rollout", false)
}

// advanceStage moves a rollout to its next stage, or finishes it. It reports
// whether the rollout continues.
func advanceStage(ro *Rollout, stages []string, why string) bool {
	if ro.Stage+1 >= len(stages) {
		ro.finish("done", "every agent runs "+ro.Hash+"; "+why)
		return false
	}
	ro.Stage++
	ro.StageStarted = time.Now()
	ro.note(fmt.Sprintf("stage %d of %d (%s); %s", ro.Stage+1, len(stages), stageLabel(stages, ro.Stage), why))
	return true
}

// haltRollout sends every agent back to the stable version and tells the
// ops webhook.
func (s *Server) haltRollout(ctx context.Context, name, id, reason string) {
	g, err := s.store.MutateGroup(name, func(g *GroupRecord) error {
		if g.RolloutState == nil || g.RolloutState.ID != id || g.RolloutState.Status != "running" {
			return errors.New("rollout changed meanwhile")
		}
		g.RolloutState.finish("halted", reason)
		return nil
	})
	if err != nil {
		return
	}
	ro := g.RolloutState
	s.log.Warn("rollout halted", "group", name, "reason", reason)
	s.audit.system("rollout", "rollout", "group.rollout.halt", name, name, reason, "")
	settings := s.store.Settings()
	a := alert.Alert{Kind: alert.KindRollout, Agent: "dashboard", Host: "dashboard", Group: name, Rule: "rollout",
		Severity: "warning", Line: fmt.Sprintf("rules %s halted, agents are back on %s: %s", ro.Hash, ro.StableHash, reason),
		Time: time.Now(), Via: "dashboard"}
	if h := s.fleet.opsHook(name, settings); h != nil {
		s.fleet.emit(a, []*alert.Hook{h})
	}
	s.syncGroup(ctx, name, "rollout halted", false)
}

// handleRolloutAction lets an editor steer a rollout:
//
//	promote      judge the current stage now and move on
//	promote_all  send the new version to every agent now
//	retry        start a halted rollout over from the first stage
//	abort        make the stable version the group's rules again
func (s *Server) handleRolloutAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Action string `json:"action"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	actor := authOf(r).id.User
	g, ok := s.store.Group(name)
	if !ok || g.RolloutState == nil {
		writeErr(w, http.StatusNotFound, errors.New("this group has no rollout"))
		return
	}
	ro := g.RolloutState
	var err error
	switch req.Action {
	case "promote", "promote_all":
		if ro.Status != "running" {
			writeErr(w, http.StatusConflict, fmt.Errorf("the rollout is %s", ro.Status))
			return
		}
		_, err = s.store.MutateGroup(name, func(g *GroupRecord) error {
			why := "promoted by " + actor
			if req.Action == "promote_all" {
				g.RolloutState.Stage = len(g.Rollout.stages()) - 1
			}
			advanceStage(g.RolloutState, g.Rollout.stages(), why)
			return nil
		})
	case "retry":
		if ro.Status != "halted" {
			writeErr(w, http.StatusConflict, errors.New("only a halted rollout can be retried"))
			return
		}
		_, err = s.store.MutateGroup(name, func(g *GroupRecord) error {
			ro := g.RolloutState
			ro.ID, ro.Stage, ro.Status, ro.Reason, ro.StageStarted = randomID(), 0, "running", "", time.Now()
			ro.note("retried by " + actor + ", back to stage 1 with other canaries")
			return nil
		})
	case "abort":
		if !ro.active() {
			writeErr(w, http.StatusConflict, fmt.Errorf("the rollout is already %s", ro.Status))
			return
		}
		stable, ok := s.store.Version(name, ro.StableHash)
		if !ok {
			writeErr(w, http.StatusConflict, errors.New("the stable version is no longer stored; roll back to a version instead"))
			return
		}
		err = s.store.SetGroupRules(name, []byte(stable.Rules), RuleVersion{Author: actor, Source: "rollout-abort",
			Note: "rollout of " + ro.Hash + " aborted"}, func(g *GroupRecord) {
			g.RolloutState.finish("aborted", "aborted by "+actor+"; every agent is back on "+stable.Hash)
			if g.Source == "git" {
				g.GitPaused = "rollout of " + ro.Hash + " aborted by " + actor + "; sync from git to follow git again"
			}
		})
		if err == nil {
			s.audit.record(r, "group.rollout.abort", name, name, "ok", ro.Hash+" → "+stable.Hash, lineDiff(g.Rules, stable.Rules))
		}
	default:
		writeErr(w, http.StatusBadRequest, errors.New("action must be promote, promote_all, retry or abort"))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if req.Action != "abort" {
		s.audit.record(r, "group.rollout."+req.Action, name, name, "ok", ro.Hash, "")
	}
	if err := s.syncGroup(r.Context(), name, "rollout "+req.Action, false); err != nil && !errors.Is(err, errSyncing) {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	g, _ = s.store.Group(name)
	writeJSON(w, http.StatusOK, map[string]any{"rollout": g.RolloutState, "state": s.snapshotState(name)})
}

// ---- dry run ----

// handleDryRun replays the last ?window= of every member's logs through the
// posted rules (and the group's current ones), on each agent, in parallel.
func (s *Server) handleDryRun(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.store.Group(name); !ok {
		writeErr(w, http.StatusNotFound, errors.New("group not found"))
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRulesSize))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	if _, err := validateForDashboard(raw); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "1h"
	}
	if d, err := time.ParseDuration(window); err != nil || d <= 0 || d > 3*time.Hour {
		writeErr(w, http.StatusBadRequest, errors.New("window must be a duration up to 3h"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 80*time.Second)
	defer cancel()

	type agentResult struct {
		Agent  string          `json:"agent"`
		OK     bool            `json:"ok"`
		Error  string          `json:"error,omitempty"`
		Result json.RawMessage `json:"result,omitempty"`
	}
	type ruleTotal struct {
		Name      string `json:"name"`
		Current   int    `json:"current"`
		Candidate int    `json:"candidate"`
		Matches   uint64 `json:"matches"`
		Agents    int    `json:"agents"` // agents where the candidate rule would alert
	}
	members := s.store.Members(name)
	results := make([]agentResult, len(members))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, a := range members {
		wg.Add(1)
		go func(i int, a AgentRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := agentResult{Agent: a.Name}
			hdr := http.Header{}
			hdr.Set("Content-Type", "application/yaml")
			resp, err := s.client(a).callLong(ctx, http.MethodPost, "/api/v1/rules/dryrun?window="+window, strings.NewReader(string(raw)), hdr)
			if err != nil {
				res.Error = err.Error()
				results[i] = res
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody))
			resp.Body.Close()
			switch {
			case resp.StatusCode == http.StatusNotFound:
				res.Error = "this agent is too old for dry runs; upgrade it"
			case resp.StatusCode != http.StatusOK:
				var e struct {
					Error string `json:"error"`
				}
				json.Unmarshal(body, &e)
				res.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, e.Error)
			default:
				res.OK, res.Result = true, body
			}
			results[i] = res
		}(i, a)
	}
	wg.Wait()

	totals := map[string]*ruleTotal{}
	var order []string
	get := func(n string) *ruleTotal {
		if t := totals[n]; t != nil {
			return t
		}
		totals[n] = &ruleTotal{Name: n}
		order = append(order, n)
		return totals[n]
	}
	var current, candidate, ok int
	for _, res := range results {
		if !res.OK {
			continue
		}
		var dr struct {
			Current, Candidate struct {
				Alerts int `json:"alerts"`
				Rules  []struct {
					Name    string `json:"name"`
					Alerts  int    `json:"alerts"`
					Matches uint64 `json:"matches"`
				} `json:"rules"`
			}
		}
		if json.Unmarshal(res.Result, &dr) != nil {
			continue
		}
		ok++
		current += dr.Current.Alerts
		candidate += dr.Candidate.Alerts
		for _, r := range dr.Candidate.Rules {
			t := get(r.Name)
			t.Candidate += r.Alerts
			t.Matches += r.Matches
			if r.Alerts > 0 {
				t.Agents++
			}
		}
		for _, r := range dr.Current.Rules {
			get(r.Name).Current += r.Alerts
		}
	}
	rulesOut := make([]ruleTotal, 0, len(order))
	for _, n := range order {
		rulesOut = append(rulesOut, *totals[n])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window": window, "agents": results, "agents_ok": ok,
		"current_alerts": current, "candidate_alerts": candidate, "rules": rulesOut,
	})
}

// ---- local rules (per-agent overlay) ----

func (s *Server) handleGetLocalRules(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.store.Agent(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("unknown agent"))
		return
	}
	resp, err := s.client(rec).call(r.Context(), http.MethodGet, "/api/v1/rules/local", nil, nil)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		writeErr(w, http.StatusNotImplemented, errors.New("this agent is too old for local rules; upgrade it"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, maxProxyBody))
}

func (s *Server) handlePutLocalRules(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.store.Agent(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("unknown agent"))
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRulesSize))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	group := EffectiveGroup(rec, s.store.Groups())
	c := s.client(rec)
	var before string
	if old, err := c.call(r.Context(), http.MethodGet, "/api/v1/rules/local", nil, nil); err == nil {
		var cur struct {
			Rules string `json:"rules"`
		}
		json.NewDecoder(io.LimitReader(old.Body, maxProxyBody)).Decode(&cur)
		old.Body.Close()
		before = cur.Rules
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/yaml")
	hdr.Set("X-Rules-Origin", "dashboard")
	resp, err := c.call(r.Context(), http.MethodPut, "/api/v1/rules/local", strings.NewReader(string(raw)), hdr)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody))
	if resp.StatusCode < 300 {
		s.audit.record(r, "agent.local_rules.update", rec.Name, group, "ok", "", lineDiff(before, string(raw)))
	} else {
		s.audit.record(r, "agent.local_rules.update", rec.Name, group, "failed", fmt.Sprintf("agent answered HTTP %d", resp.StatusCode), "")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
