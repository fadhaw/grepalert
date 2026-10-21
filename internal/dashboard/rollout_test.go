package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/agent"
	"github.com/fadhaw/grepalert/internal/alert"
	"github.com/fadhaw/grepalert/internal/rules"
)

type fleetHarness struct {
	*harness
	agents map[string]*agent.Agent
	log    string
	hook   *hookRecorder
}

// newFleetHarness runs n direct agents that all tail one log file, in a
// group "web" with staged rollouts on.
func newFleetHarness(t *testing.T, n int) *fleetHarness {
	t.Helper()
	hook := newHookRecorder(t)
	t.Setenv("WEBHOOK_URL", hook.srv.URL)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	os.WriteFile(logPath, []byte("start\n"), 0o644)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	store, err := OpenStore(filepath.Join(dir, "dash.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{}, store, log)
	fctx, stopFleet := context.WithCancel(context.Background())
	go s.RunFleet(fctx) // delivers ops alerts
	t.Cleanup(stopFleet)
	ds := httptest.NewServer(s.Handler())
	t.Cleanup(ds.Close)
	h := &fleetHarness{harness: &harness{t: t, dash: ds, srv: s}, agents: map[string]*agent.Agent{}, log: logPath, hook: hook}

	h.do("POST", "/api/groups", map[string]any{"name": "web", "source": "manual", "rules": h.rules("ERROR"),
		"ops_webhook_url": hook.srv.URL, "rollout": map[string]any{"enabled": true, "stages": []string{"1", "50%"}, "soak": "10s"}}, http.StatusOK)
	// Tests judge stages by hand, after a short soak.
	store.MutateGroup("web", func(g *GroupRecord) error { g.Rollout.Soak = "300ms"; return nil })

	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("a%d", i)
		adir := filepath.Join(dir, name)
		a := agent.New(agent.Config{Name: name, RulesFile: filepath.Join(adir, "rules.yaml"), StateFile: "off",
			PollInterval: rules.Duration(20 * time.Millisecond)}, log)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { a.Run(ctx); close(done) }()
		t.Cleanup(func() { cancel(); <-done })
		as := httptest.NewServer(a.Handler())
		t.Cleanup(as.Close)
		h.agents[name] = a
		h.do("POST", "/api/agents", map[string]any{"url": as.URL, "group": "web"}, http.StatusOK)
	}
	time.Sleep(200 * time.Millisecond) // tailers opened the log
	return h
}

func (h *fleetHarness) rules(pattern string) string {
	return fmt.Sprintf("webhooks:\n  - name: h\n    url: ${WEBHOOK_URL}\nrules:\n  - name: errors\n    files: [%q]\n    pattern: '%s'\n    webhooks: [h]\n", h.log, pattern)
}

// running counts agents per rules version.
func (h *fleetHarness) running() map[string]int {
	out := map[string]int{}
	for _, a := range h.agents {
		out[a.Rules().Hash]++
	}
	return out
}

func (h *fleetHarness) rollout() *Rollout {
	g, _ := h.srv.store.Group("web")
	return g.RolloutState
}

// judge samples the current stage, lets it soak and judges it.
func (h *fleetHarness) judge(during func()) {
	h.srv.evaluateRollout(context.Background(), "web")
	if during != nil {
		during()
	}
	time.Sleep(350 * time.Millisecond)
	h.srv.evaluateRollout(context.Background(), "web")
}

func TestStagedRolloutVersionsAndRollback(t *testing.T) {
	h := newFleetHarness(t, 4)
	v1, v2 := rules.Hash([]byte(h.rules("ERROR"))), rules.Hash([]byte(h.rules("ERROR|FATAL")))
	if got := h.running(); got[v1] != 4 {
		t.Fatalf("running = %v, want all on v1", got)
	}

	// A change starts a rollout: one canary first.
	h.do("PUT", "/api/groups/web/rules", h.rules("ERROR|FATAL"), http.StatusOK)
	if ro := h.rollout(); ro == nil || ro.Status != "running" || ro.Hash != v2 || ro.StableHash != v1 {
		t.Fatalf("rollout = %+v", ro)
	}
	if got := h.running(); got[v2] != 1 || got[v1] != 3 {
		t.Fatalf("stage 1: running = %v, want 1 on v2", got)
	}
	ov := h.do("GET", "/api/overview", nil, http.StatusOK)
	if c := ov["groups"].([]any)[0].(map[string]any)["canaries"].([]any); len(c) != 1 {
		t.Fatalf("canaries = %v", c)
	}

	var versions []versionView
	getJSON(t, h.dash.URL+"/api/groups/web/versions", &versions)
	if len(versions) != 2 || versions[0].Hash != v2 || !versions[0].Current || versions[1].Hash != v1 || !versions[1].Stable {
		t.Fatalf("versions = %+v", versions)
	}

	// Quiet stages are promoted: 50%, then everyone.
	h.judge(nil)
	if got := h.running(); got[v2] != 2 {
		t.Fatalf("stage 2: running = %v, want 2 on v2", got)
	}
	h.judge(nil)
	if got, ro := h.running(), h.rollout(); got[v2] != 4 || ro.Status != "running" || ro.Stage != 2 {
		t.Fatalf("stage 3: running = %v, rollout %+v", got, ro)
	}
	h.judge(nil)
	if ro := h.rollout(); ro.Status != "done" {
		t.Fatalf("rollout = %+v, want done", ro)
	}
	if got := h.running(); got[v2] != 4 {
		t.Fatalf("done: running = %v", got)
	}

	// A rule that fires a lot on the canary halts the rollout and sends
	// everyone back to v2.
	v3 := rules.Hash([]byte(h.rules("ERROR|SPIKE")))
	h.do("PUT", "/api/groups/web/rules", h.rules("ERROR|SPIKE"), http.StatusOK)
	var canary *agent.Agent
	for _, a := range h.agents {
		if a.Rules().Hash == v3 {
			canary = a
		}
	}
	h.judge(func() {
		f, _ := os.OpenFile(h.log, os.O_APPEND|os.O_WRONLY, 0)
		for i := 0; i < 25; i++ {
			fmt.Fprintf(f, "SPIKE %d\n", i)
		}
		f.Close()
		waitFor(t, "canary alerts", 5*time.Second, func() bool { return canary.Status().AlertsTotal >= 25 })
	})
	ro := h.rollout()
	if ro.Status != "halted" || !strings.Contains(ro.Reason, "alert spike") {
		t.Fatalf("rollout = %+v, want halted on a spike", ro)
	}
	if got := h.running(); got[v2] != 4 {
		t.Fatalf("halted: running = %v, want all back on v2", got)
	}
	waitFor(t, "ops alert", 5*time.Second, func() bool {
		for _, a := range h.hook.alerts() {
			if a.Kind == alert.KindRollout && a.Group == "web" {
				return true
			}
		}
		return false
	})

	// Retry starts over; abort makes v2 the group's rules again.
	h.do("POST", "/api/groups/web/rollout", map[string]any{"action": "retry"}, http.StatusOK)
	if ro := h.rollout(); ro.Status != "running" || ro.Stage != 0 {
		t.Fatalf("after retry: %+v", ro)
	}
	h.do("POST", "/api/groups/web/rollout", map[string]any{"action": "abort"}, http.StatusOK)
	if g, _ := h.srv.store.Group("web"); g.RulesHash != v2 || g.RolloutState.Status != "aborted" {
		t.Fatalf("after abort: hash %s, rollout %+v", g.RulesHash, g.RolloutState)
	}
	if got := h.running(); got[v2] != 4 {
		t.Fatalf("aborted: running = %v", got)
	}

	// Rules the agents refuse (an unset variable) halt at the first canary.
	bad := strings.Replace(h.rules("ERROR"), "${WEBHOOK_URL}", "${GREPALERT_TEST_UNSET}", 1)
	h.do("PUT", "/api/groups/web/rules", bad, http.StatusOK)
	h.srv.evaluateRollout(context.Background(), "web")
	if ro := h.rollout(); ro.Status != "halted" || !strings.Contains(ro.Reason, "failed to apply") {
		t.Fatalf("rollout = %+v, want halted on rejected rules", ro)
	}

	// Rolling back is immediate, on every agent, and recorded as a version.
	h.do("POST", "/api/groups/web/rollback", map[string]any{"hash": v1}, http.StatusOK)
	if got := h.running(); got[v1] != 4 {
		t.Fatalf("rollback: running = %v", got)
	}
	if ro := h.rollout(); ro.Status != "aborted" {
		t.Fatalf("rollout after rollback = %+v", ro)
	}
	getJSON(t, h.dash.URL+"/api/groups/web/versions", &versions)
	if versions[0].Source != "rollback" || versions[0].Hash != v1 || !versions[0].Current {
		t.Fatalf("newest version = %+v", versions[0])
	}
	resp, _ := http.Get(h.dash.URL + "/api/groups/web/versions/" + v2)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(raw) != h.rules("ERROR|FATAL") {
		t.Fatalf("version %s = %q", v2, raw)
	}
}

func TestDryRunAndLocalRules(t *testing.T) {
	h := newFleetHarness(t, 2)
	f, _ := os.OpenFile(h.log, os.O_APPEND|os.O_WRONLY, 0)
	for i := 0; i < 30; i++ {
		fmt.Fprintf(f, "WARN disk %d%%\n", 80+i%10)
	}
	f.Close()

	r := h.do("POST", "/api/groups/web/dryrun?window=1h", h.rules("WARN disk"), http.StatusOK)
	if r["agents_ok"] != 2.0 || r["candidate_alerts"] != 60.0 || r["current_alerts"] != 0.0 {
		t.Fatalf("dry run = %v", r)
	}
	if rs := r["rules"].([]any); len(rs) != 1 || rs[0].(map[string]any)["agents"] != 2.0 {
		t.Fatalf("dry run rules = %v", rs)
	}
	h.do("POST", "/api/groups/web/dryrun?window=9h", h.rules("x"), http.StatusBadRequest)

	// One VM gets an extra rule on top of the group's.
	local := fmt.Sprintf("rules:\n  - name: disk\n    files: [%q]\n    pattern: 'WARN disk'\n    webhooks: [h]\n", h.log)
	h.do("PUT", "/api/agents/a1/local-rules", local, http.StatusOK)
	got := h.do("GET", "/api/agents/a1/local-rules", nil, http.StatusOK)
	if got["rules"] != local || got["rejected"] != "" {
		t.Fatalf("local rules = %v", got)
	}
	if n := len(h.agents["a1"].Active().Rules); n != 2 {
		t.Fatalf("a1 runs %d rules, want 2", n)
	}
	if n := len(h.agents["a2"].Active().Rules); n != 1 {
		t.Fatalf("a2 runs %d rules, want 1", n)
	}
	// The group's version is unchanged, so the agent stays in sync.
	g, _ := h.srv.store.Group("web")
	if h.agents["a1"].Rules().Hash != g.RulesHash {
		t.Fatal("the overlay changed the agent's group rules hash")
	}
	clash := fmt.Sprintf("rules:\n  - name: errors\n    files: [%q]\n    pattern: x\n    webhooks: [h]\n", h.log)
	h.do("PUT", "/api/agents/a1/local-rules", clash, http.StatusUnprocessableEntity)
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestStageSize(t *testing.T) {
	for _, c := range []struct {
		stage string
		total int
		want  int
	}{{"1", 10, 1}, {"10%", 10, 1}, {"10%", 11, 2}, {"50%", 3, 2}, {"100%", 7, 7}, {"5", 3, 3}, {"10%", 0, 1}} {
		if got := stageSize(c.stage, c.total); got != c.want && c.total > 0 {
			t.Errorf("stageSize(%q, %d) = %d, want %d", c.stage, c.total, got, c.want)
		}
	}
	rs := RolloutSettings{Enabled: true, Stages: []string{"1", "25%"}}
	if err := rs.validate(); err != nil || strings.Join(rs.Stages, ",") != "1,25%,100%" || rs.Soak != "5m" {
		t.Fatalf("validate = %v, %+v", err, rs)
	}
	if err := (&RolloutSettings{Enabled: true, Stages: []string{"0"}}).validate(); err == nil {
		t.Fatal("stage 0 accepted")
	}
}
