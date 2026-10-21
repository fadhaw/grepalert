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
	"sync"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/agent"
	"github.com/fadhaw/grepalert/internal/alert"
)

// hookRecorder is a webhook receiver that records alerts.
type hookRecorder struct {
	srv  *httptest.Server
	mu   sync.Mutex
	got  []alert.Alert
	fail bool
}

func newHookRecorder(t *testing.T) *hookRecorder {
	h := &hookRecorder{}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a alert.Alert
		json.NewDecoder(r.Body).Decode(&a)
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		h.got = append(h.got, a)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hookRecorder) alerts() []alert.Alert {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]alert.Alert(nil), h.got...)
}

func (h *hookRecorder) waitN(t *testing.T, n int) []alert.Alert {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d webhook calls", n), 5*time.Second, func() bool { return len(h.alerts()) >= n })
	time.Sleep(50 * time.Millisecond) // make sure no extra ones follow
	return h.alerts()
}

func newFleetServer(t *testing.T) (*Server, *fakeClock, context.CancelFunc) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "d.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	s.fleet.now = clk.now
	ctx, cancel := context.WithCancel(context.Background())
	s.fleet.sender.Start(ctx, 2)
	t.Cleanup(cancel)
	return s, clk, cancel
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func matchAlert(agentName, code string) alert.Alert {
	return alert.Alert{Kind: alert.KindMatch, Agent: agentName, Group: "api", Rule: "errors", GroupKey: code,
		Severity: "warning", File: "/var/log/app.log", Line: "ERROR code=" + code + " on " + agentName}
}

func TestFleetDedupe(t *testing.T) {
	s, clk, _ := newFleetServer(t)
	rec := newHookRecorder(t)
	hooks := []*alert.Hook{{Name: "slack", URL: rec.srv.URL}}
	for _, h := range hooks {
		h.Compile()
	}
	g := &GroupRecord{Name: "api", Fleet: FleetSettings{Wait: "5s", Window: "5m"}}
	s.store.AddGroup(GroupRecord{Name: "api", Source: "manual", Fleet: g.Fleet}, "")

	// 50 hosts report the same error within the wait period.
	for i := 1; i <= 50; i++ {
		s.fleet.ingest(matchAlert(fmt.Sprintf("web-%02d", i), "DB_TIMEOUT"), hooks, g)
	}
	// A different error code is a different alert.
	s.fleet.ingest(matchAlert("web-01", "PAYMENT"), hooks, g)
	s.fleet.sweep()
	if n := len(rec.alerts()); n != 0 {
		t.Fatalf("sent %d alerts before the wait period ended", n)
	}

	clk.add(5 * time.Second)
	s.fleet.sweep()
	got := rec.waitN(t, 2)
	if len(got) != 2 {
		t.Fatalf("got %d alerts, want 2 (one per error code)", len(got))
	}
	var db alert.Alert
	for _, a := range got {
		if a.GroupKey == "DB_TIMEOUT" {
			db = a
		}
	}
	if db.HostCount != 50 || len(db.Hosts) != maxListHosts || db.Via != "dashboard" || db.ID == "" ||
		!strings.Contains(db.Text, "on 50 hosts") || !strings.Contains(db.Text, "+40") {
		t.Fatalf("fleet alert = %+v", db)
	}

	// During the window: held back. Window end: one summary.
	for i := 1; i <= 7; i++ {
		s.fleet.ingest(matchAlert(fmt.Sprintf("web-%02d", i), "DB_TIMEOUT"), hooks, g)
	}
	// An agent's own suppression summary counts into the window too.
	sum := matchAlert("web-03", "DB_TIMEOUT")
	sum.Kind, sum.Suppressed = alert.KindSummary, 20
	s.fleet.ingest(sum, hooks, g)
	clk.add(4 * time.Minute)
	s.fleet.sweep()
	if len(rec.alerts()) != 2 {
		t.Fatal("alerts were sent during the fleet window")
	}
	clk.add(time.Minute)
	s.fleet.sweep()
	got = rec.waitN(t, 3)
	if len(got) != 3 {
		t.Fatalf("got %d alerts, want a third (summary)", len(got))
	}
	summary := got[2]
	if summary.Kind != alert.KindFleetSummary || summary.Suppressed != 27 || summary.HostCount != 7 {
		t.Fatalf("summary = %+v", summary)
	}

	h := s.fleet.History("api", 10)
	if len(h) != 3 || h[0].Kind != alert.KindFleetSummary || h[0].Status != "sent" {
		t.Fatalf("history = %+v", h)
	}
}

func TestFleetSilence(t *testing.T) {
	s, clk, _ := newFleetServer(t)
	rec := newHookRecorder(t)
	hooks := []*alert.Hook{{Name: "slack", URL: rec.srv.URL}}
	hooks[0].Compile()
	s.store.AddGroup(GroupRecord{Name: "api", Source: "manual", Fleet: FleetSettings{Wait: "0s"}}, "")
	g, _ := s.store.Group("api")

	sl, err := s.store.AddSilence(Silence{Group: "api", Rules: []string{"errors"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour), Reason: "patching"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.fleet.ingest(matchAlert("web-01", "DB_TIMEOUT"), hooks, &g)
	}
	other := matchAlert("web-01", "X")
	other.Rule = "panics" // not covered by the silence
	s.fleet.ingest(other, hooks, &g)
	clk.add(time.Second)
	s.fleet.sweep()
	got := rec.waitN(t, 1)
	if len(got) != 1 || got[0].Rule != "panics" {
		t.Fatalf("got %+v, want only the unsilenced rule", got)
	}
	h := s.fleet.History("api", 10)
	silenced := 0
	for _, e := range h {
		if e.Status == "silenced" && e.Silence == sl.ID {
			silenced++
		}
	}
	if silenced != 1 {
		t.Fatalf("history = %+v, want one silenced entry for repeated matches", h)
	}

	// The agent gets the silence with its polls, for direct delivery.
	a := AgentRecord{Name: "web-01", Group: "api"}
	if got := s.silencesFor(a); len(got) != 1 || got[0]["id"] != sl.ID {
		t.Fatalf("silencesFor = %v", got)
	}
	s.store.ExpireSilence(sl.ID)
	if got := s.silencesFor(a); len(got) != 0 {
		t.Fatal("expired silence still sent to agents")
	}
}

func TestAgentDownAlerts(t *testing.T) {
	s, clk, _ := newFleetServer(t)
	ops := newHookRecorder(t)
	s.store.AddGroup(GroupRecord{Name: "api", Source: "manual"}, "")
	s.store.data.Settings = Settings{OpsWebhook: OpsWebhook{URL: ops.srv.URL}, AgentDownAfter: "1m"}
	rec, secret, err := s.store.Enroll(EnrollRequest{Token: "boot", Name: "vm-1", Labels: map[string]string{"a": "b"}}, "boot")
	if err != nil {
		t.Fatal(err)
	}
	s.store.UpdateAgent("vm-1", func(a *AgentRecord) error { a.Group = "api"; return nil })
	_ = secret
	tun := s.tunnelFor(rec.ID)
	tun.lastSeen.Store(clk.now().UnixNano()) // seen "now" in fake time

	ctx := context.Background()
	s.fleet.checkAgents(ctx) // offline (no poll), but not for long
	clk.add(30 * time.Second)
	s.fleet.checkAgents(ctx)
	if len(ops.alerts()) != 0 {
		t.Fatal("agent-down sent too early")
	}
	clk.add(31 * time.Second)
	s.fleet.checkAgents(ctx)
	s.fleet.checkAgents(ctx) // only once
	got := ops.waitN(t, 1)
	if len(got) != 1 || got[0].Kind != alert.KindAgentDown || got[0].Agent != "vm-1" || got[0].Group != "api" {
		t.Fatalf("got %+v", got)
	}
	if _, down := s.fleet.downStates()["vm-1"]; !down {
		t.Fatal("overview should show the agent as down")
	}

	// It polls again: agent-up.
	tun.polling.Add(1)
	s.fleet.checkAgents(ctx)
	tun.polling.Add(-1)
	got = ops.waitN(t, 2)
	if len(got) != 2 || got[1].Kind != alert.KindAgentUp {
		t.Fatalf("got %+v", got)
	}

	// Revoked agents never alert.
	s.store.UpdateAgent("vm-1", func(a *AgentRecord) error { a.Revoked = true; return nil })
	clk.add(time.Hour)
	s.fleet.checkAgents(ctx)
	if len(ops.alerts()) != 2 {
		t.Fatal("revoked agent triggered an alert")
	}
}

// End to end: a connected agent's alerts reach the webhook through the
// dashboard; when the dashboard is unreachable the agent delivers directly,
// still honouring the dashboard's silences.
func TestAlertsThroughDashboardWithFallback(t *testing.T) {
	dir := t.TempDir()
	hook := newHookRecorder(t)
	t.Setenv("WEBHOOK_URL", hook.srv.URL)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, _ := OpenStore(filepath.Join(dir, "d.json"))
	srv := New(Config{EnrollmentToken: "boot"}, store, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.RunFleet(ctx)

	var down sync.Mutex
	dashDown := false
	ds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		down.Lock()
		d := dashDown
		down.Unlock()
		if d {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		srv.Handler().ServeHTTP(w, r)
	}))
	defer ds.Close()
	defer srv.Shutdown()

	logPath := filepath.Join(dir, "app.log")
	appendLine := func(s string) {
		f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		f.WriteString(s + "\n")
		f.Close()
	}
	appendLine("start")
	rulesYAML := fmt.Sprintf("webhooks:\n  - name: h\n    url: ${WEBHOOK_URL}\nrules:\n  - name: errors\n    files: [%q]\n    pattern: 'ERROR (?P<code>\\w+)'\n    webhooks: [h]\n    suppress: {window: 1m, group_by: code}\n", logPath)
	store.AddGroup(GroupRecord{Name: "api", Source: "manual", Rules: rulesYAML, Selector: map[string]string{"role": "api"},
		Fleet: FleetSettings{Wait: "200ms", Window: "1m"}}, "")

	ra := startConnectedAgent(t, ds.URL, "boot", filepath.Join(dir, "agent"), map[string]string{"role": "api"})
	g, _ := store.Group("api")
	waitFor(t, "group rules", 5*time.Second, func() bool { return ra.a.Rules().Hash == g.RulesHash })
	time.Sleep(700 * time.Millisecond) // tailer opened the file

	appendLine("ERROR A1")
	got := hook.waitN(t, 1)
	if got[0].Via != "dashboard" || got[0].Agent != "edge-01" || got[0].Group != "api" || got[0].ID == "" {
		t.Fatalf("alert = %+v, want delivered via the dashboard", got[0])
	}

	// Silence rule "errors", then take the dashboard down.
	store.AddSilence(Silence{Group: "api", Rules: []string{"errors"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)})
	time.Sleep(200 * time.Millisecond)
	srv.wakeTunnel(store.Agents()[0].ID) // next poll carries the silence
	waitFor(t, "agent knows the silence", 5*time.Second, func() bool { return ra.a.Status().Dashboard.Connected })
	time.Sleep(300 * time.Millisecond)
	down.Lock()
	dashDown = true
	down.Unlock()
	srv.wakeTunnel(store.Agents()[0].ID)
	waitFor(t, "agent notices the dashboard is down", 30*time.Second, func() bool {
		st := ra.a.Status()
		return !st.Dashboard.Connected && time.Since(st.Dashboard.LastContact) > 1500*time.Millisecond
	})
	appendLine("ERROR B2") // silenced: must not be delivered directly either
	time.Sleep(1500 * time.Millisecond)
	if n := len(hook.alerts()); n != 1 {
		t.Fatalf("silenced alert was delivered during fallback (%d alerts)", n)
	}

	store.ExpireSilence(store.Silences()[0].ID)
	// The agent still has the old silence list (the dashboard is down), so
	// it keeps honouring it until its end time; use a rule it does not cover.
	ra.a.ApplyRules([]byte(strings.Replace(rulesYAML, "name: errors", "name: errors2", 1)), "test")
	time.Sleep(700 * time.Millisecond)
	appendLine("ERROR C3")
	got = hook.waitN(t, 2)
	if got[1].Via != "agent" || !strings.Contains(got[1].Text, "dashboard unreachable") {
		t.Fatalf("fallback alert = %+v", got[1])
	}
	_ = agent.Version
}

// A silence that starts while a fleet window is open also covers the
// summary sent when the window closes.
func TestSilenceCoversOpenWindow(t *testing.T) {
	s, clk, _ := newFleetServer(t)
	rec := newHookRecorder(t)
	hooks := []*alert.Hook{{Name: "slack", URL: rec.srv.URL}}
	hooks[0].Compile()
	s.store.AddGroup(GroupRecord{Name: "api", Source: "manual", Fleet: FleetSettings{Wait: "1s", Window: "1m"}}, "")
	g, _ := s.store.Group("api")
	s.fleet.ingest(matchAlert("web-01", "K"), hooks, &g)
	clk.add(time.Second)
	s.fleet.sweep()
	rec.waitN(t, 1)
	s.fleet.ingest(matchAlert("web-02", "K"), hooks, &g) // held back
	s.store.AddSilence(Silence{Group: "api", StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)})
	clk.add(time.Minute)
	s.fleet.sweep()
	time.Sleep(200 * time.Millisecond)
	if n := len(rec.alerts()); n != 1 {
		t.Fatalf("summary was sent during the silence (%d calls)", n)
	}
	if h := s.fleet.History("api", 1); len(h) != 1 || h[0].Kind != alert.KindFleetSummary || h[0].Status != "silenced" {
		t.Fatalf("history = %+v", h)
	}
}
