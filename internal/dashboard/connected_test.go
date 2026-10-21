package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/agent"
	"github.com/fadhaw/grepalert/internal/rules"
)

// waitFor polls cond until it is true or the timeout expires.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type runningAgent struct {
	a      *agent.Agent
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

func startConnectedAgent(t *testing.T, dashURL, token, dir string, labels map[string]string) *runningAgent {
	t.Helper()
	cfg := agent.Config{
		Name:      "edge-01",
		RulesFile: filepath.Join(dir, "rules.yaml"),
		StateFile: "off",
		Labels:    labels,
		Dashboard: agent.DashboardConfig{URL: dashURL, EnrollmentToken: token, FallbackAfter: rules.Duration(time.Second)},
	}
	a := agent.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	ra := &runningAgent{a: a, cancel: cancel, done: make(chan error, 1)}
	go func() { ra.done <- a.Run(ctx) }()
	t.Cleanup(ra.stop)
	return ra
}

func (r *runningAgent) stop() { r.once.Do(r.doStop) }

func (r *runningAgent) doStop() {
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
	}
}

func TestConnectedAgentLifecycle(t *testing.T) {
	t.Setenv("WEBHOOK_URL", "http://127.0.0.1:1/hook")
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := OpenStore(filepath.Join(dir, "dash.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Config{EnrollmentToken: "boot-token"}, store, log)
	ds := httptest.NewServer(srv.Handler())
	defer ds.Close()
	defer srv.Shutdown() // runs before Close: releases held polls
	h := &harness{t: t, dash: ds, srv: srv}

	// A group that auto-adds agents labelled role=edge.
	h.do("POST", "/api/groups", map[string]any{"name": "edge", "source": "manual", "rules": groupRules,
		"selector": map[string]string{"role": "edge"}}, http.StatusOK)
	g, _ := store.Group("edge")

	// Wrong token: the agent never enrolls.
	bad := startConnectedAgent(t, ds.URL, "wrong", filepath.Join(dir, "bad"), map[string]string{"role": "edge"})
	time.Sleep(300 * time.Millisecond)
	bad.stop()
	if len(store.Agents()) != 0 {
		t.Fatal("agent enrolled with a wrong token")
	}

	// Enroll with the config token; it joins "edge" by label and gets its rules
	// pushed through the tunnel — no inbound port on the agent.
	agentDir := filepath.Join(dir, "agent")
	ra := startConnectedAgent(t, ds.URL, "boot-token", agentDir, map[string]string{"role": "edge", "env": "prod"})
	waitFor(t, "group rules on the agent", 5*time.Second, func() bool { return ra.a.Rules().Hash == g.RulesHash })

	rec, ok := store.Agent("edge-01")
	if !ok || !rec.Connected() || rec.EnrolledVia != "config" || rec.Labels["env"] != "prod" || rec.Labels["os"] == "" {
		t.Fatalf("stored agent = %+v", rec)
	}
	firstID := rec.ID

	var ov struct {
		Agents []agentView `json:"agents"`
	}
	raw, _ := json.Marshal(h.do("GET", "/api/overview", nil, http.StatusOK))
	json.Unmarshal(raw, &ov)
	if len(ov.Agents) != 1 || !ov.Agents[0].Online || ov.Agents[0].Group != "edge" || ov.Agents[0].Assigned || ov.Agents[0].Mode != "connected" {
		t.Fatalf("overview agent = %+v", ov.Agents[0])
	}

	// Rules edits reach it through the tunnel; so do proxied reads.
	newRules := strings.Replace(groupRules, "ERROR", "PANIC", 1)
	h.do("PUT", "/api/groups/edge/rules", newRules, http.StatusOK)
	if got := string(ra.a.Rules().Raw); got != newRules {
		t.Fatalf("rules not pushed through the tunnel:\n%s", got)
	}
	h.do("GET", "/api/agents/edge-01/events", nil, http.StatusOK)

	// Restart: the agent reuses its saved identity instead of enrolling again.
	ra.stop()
	ra = startConnectedAgent(t, ds.URL, "", agentDir, map[string]string{"role": "edge", "env": "prod"})
	waitFor(t, "reconnect", 5*time.Second, func() bool {
		st := ra.a.Status()
		return st.Dashboard != nil && st.Dashboard.Connected
	})
	if rec, _ := store.Agent("edge-01"); rec.ID != firstID || len(store.Agents()) != 1 {
		t.Fatal("restart should reuse the identity, not re-enroll")
	}

	// Revoke: the dashboard stops talking to it, and the agent sees it.
	h.do("POST", "/api/agents/edge-01/revoke", nil, http.StatusOK)
	waitFor(t, "agent to notice revocation", 30*time.Second, func() bool {
		st := ra.a.Status()
		return st.Dashboard != nil && !st.Dashboard.Connected && strings.Contains(st.Dashboard.LastError, "revoked")
	})
	if m := store.Members("edge"); len(m) != 0 {
		t.Fatal("revoked agents must not be group members")
	}
	h.do("POST", "/api/agents/edge-01/allow", nil, http.StatusOK)

	// Dashboard data lost: the agent is unknown and enrolls again by itself.
	ra.stop()
	store2, _ := OpenStore(filepath.Join(dir, "dash2.json"))
	srv2 := New(Config{EnrollmentToken: "boot-token"}, store2, log)
	defer srv2.Shutdown()
	srv.Shutdown()
	ds.Config.Handler = srv2.Handler()
	ra = startConnectedAgent(t, ds.URL, "boot-token", agentDir, map[string]string{"role": "edge"})
	waitFor(t, "re-enrollment", 10*time.Second, func() bool {
		r, ok := store2.Agent("edge-01")
		return ok && r.ID != "" && r.ID != firstID
	})
	waitFor(t, "agent connected again", 10*time.Second, func() bool {
		st := ra.a.Status()
		return st.Dashboard != nil && st.Dashboard.Connected
	})
}

func TestEnrollmentTokens(t *testing.T) {
	dir := t.TempDir()
	store, _ := OpenStore(filepath.Join(dir, "d.json"))
	tok, raw, err := store.CreateToken("vm-images", time.Hour)
	if err != nil || !strings.HasPrefix(raw, enrollPrefix) || tok.Hash == raw {
		t.Fatalf("CreateToken: %v %q", err, raw)
	}
	enroll := func(token, name string) error {
		_, _, err := store.Enroll(EnrollRequest{Token: token, Name: name, Labels: map[string]string{"a": "b"}}, "")
		return err
	}
	if err := enroll(raw, "vm-1"); err != nil {
		t.Fatal(err)
	}
	if err := enroll("gae_nope", "vm-2"); err == nil {
		t.Fatal("unknown token accepted")
	}
	store.RevokeToken(tok.ID)
	if err := enroll(raw, "vm-3"); err == nil {
		t.Fatal("revoked token accepted")
	}
	_, raw2, _ := store.CreateToken("short", time.Nanosecond)
	time.Sleep(time.Millisecond)
	if err := enroll(raw2, "vm-4"); err == nil {
		t.Fatal("expired token accepted")
	}
	// A direct agent's name cannot be taken over by enrollment.
	store.AddAgent(AgentRecord{Name: "direct-1", URL: "http://x"})
	_, raw3, _ := store.CreateToken("third", 0)
	if err := enroll(raw3, "direct-1"); err == nil {
		t.Fatal("enrollment took over a direct agent's name")
	}
	// The data file never contains raw tokens or secrets.
	data, _ := json.Marshal(store.data)
	if strings.Contains(string(data), raw) || strings.Contains(string(data), raw3) {
		t.Fatal("raw token stored")
	}
}

func TestSelectors(t *testing.T) {
	groups := []GroupRecord{
		{Name: "a-web", Selector: map[string]string{"role": "web"}},
		{Name: "b-prod-web", Selector: map[string]string{"role": "web", "env": "prod"}},
		{Name: "c-none"},
	}
	cases := []struct {
		a    AgentRecord
		want string
	}{
		{AgentRecord{Labels: map[string]string{"role": "web", "env": "prod"}}, "a-web"}, // first by name
		{AgentRecord{Labels: map[string]string{"role": "db"}}, ""},
		{AgentRecord{Group: "c-none", Labels: map[string]string{"role": "web"}}, "c-none"}, // admin wins
		{AgentRecord{}, ""},
	}
	for i, c := range cases {
		if got := EffectiveGroup(c.a, groups); got != c.want {
			t.Errorf("case %d: got %q, want %q", i, got, c.want)
		}
	}
	if err := CheckLabels(map[string]string{"ok": "v", "bad key": "x"}); err == nil {
		t.Error("invalid label accepted")
	}
}
