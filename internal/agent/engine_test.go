package agent

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

const testRules = `
webhooks:
  - name: hook
    url: http://127.0.0.1:1/
rules:
  - name: errors
    files: [/var/log/app.log]
    pattern: 'ERROR (?P<code>\w+)'
    exclude: 'ignored'
    webhooks: [hook]
    suppress:
      window: 1m
      max_alerts: 2
      group_by: code
`

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

func newTestEngine(t *testing.T, src string) (*engine, *[]Alert, *fakeClock) {
	t.Helper()
	c, err := rules.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var got []Alert
	e := newEngine("a1", "host", newRing(10), func(a Alert, _ *rules.CompiledRule) { got = append(got, a) })
	clk := &fakeClock{t: time.Unix(1000, 0)}
	e.now = clk.now
	byFile := map[string][]*rules.CompiledRule{}
	for _, r := range c.Rules {
		for _, f := range r.Files {
			byFile[f] = append(byFile[f], r)
		}
	}
	e.setSnapshot(&snapshot{rules: c, byFile: byFile})
	return e, &got, clk
}

func TestSuppression(t *testing.T) {
	e, got, clk := newTestEngine(t, testRules)
	const f = "/var/log/app.log"

	for i := 0; i < 10; i++ {
		e.process(f, []byte("ERROR E1 boom"))
	}
	e.process(f, []byte("ERROR E2 other group"))
	e.process(f, []byte("ERROR E1 ignored"))
	e.process(f, []byte("INFO fine"))
	e.process("/other.log", []byte("ERROR E1"))

	if len(*got) != 3 {
		t.Fatalf("alerts = %d, want 3 (2 for E1, 1 for E2)", len(*got))
	}
	if (*got)[0].Groups["code"] != "E1" || (*got)[2].GroupKey != "E2" {
		t.Fatalf("unexpected groups: %+v", *got)
	}
	st := e.ruleStats()["errors"]
	if st.Matches != 11 || st.Alerts != 3 || st.Suppressed != 8 {
		t.Fatalf("stats = %+v", st)
	}

	// Window still open: nothing to summarise yet.
	e.sweep()
	if len(*got) != 3 {
		t.Fatal("sweep fired before window closed")
	}

	clk.t = clk.t.Add(time.Minute)
	e.sweep()
	if len(*got) != 4 {
		t.Fatalf("alerts = %d, want summary alert", len(*got))
	}
	sum := (*got)[3]
	if sum.Kind != "summary" || sum.Suppressed != 8 || sum.GroupKey != "E1" {
		t.Fatalf("summary = %+v", sum)
	}
	if e.suppressKeys() != 0 {
		t.Fatalf("suppression state not freed: %d keys", e.suppressKeys())
	}

	// New window alerts again.
	e.process(f, []byte("ERROR E1 again"))
	if len(*got) != 5 {
		t.Fatal("expected alert in new window")
	}
}

func TestSuppressionKeysAreBounded(t *testing.T) {
	e, _, _ := newTestEngine(t, testRules)
	for i := 0; i < maxSuppressKeys+500; i++ {
		e.process("/var/log/app.log", []byte(fmt.Sprintf("ERROR id%d", i)))
	}
	if n := e.suppressKeys(); n > maxSuppressKeys+1 {
		t.Fatalf("suppression keys = %d, exceeds bound", n)
	}
}

func TestReloadDropsStateOfRemovedRules(t *testing.T) {
	e, _, _ := newTestEngine(t, testRules)
	e.process("/var/log/app.log", []byte("ERROR E1"))
	c, err := rules.Parse([]byte("webhooks: []\nrules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	e.setSnapshot(&snapshot{rules: c, byFile: map[string][]*rules.CompiledRule{}})
	if e.suppressKeys() != 0 || len(e.ruleStats()) != 0 {
		t.Fatal("state of removed rule was kept")
	}
}

func TestRingIsBounded(t *testing.T) {
	r := newRing(3)
	for i := 0; i < 10; i++ {
		r.add(Event{Message: fmt.Sprint(i)})
	}
	got := r.list(0)
	if len(got) != 3 || got[0].Message != "9" || got[2].Message != "7" {
		t.Fatalf("ring = %+v", got)
	}
}

// BenchmarkProcessNoMatch shows the hot path for non-matching lines does not allocate.
func BenchmarkProcessNoMatch(b *testing.B) {
	c, _ := rules.Parse([]byte(testRules))
	e := newEngine("a", "h", newRing(10), func(Alert, *rules.CompiledRule) {})
	e.setSnapshot(&snapshot{rules: c, byFile: map[string][]*rules.CompiledRule{"/f": c.Rules}})
	line := []byte("2026-10-12 12:00:00 INFO request served in 12ms path=/api/v1/things")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.process("/f", line)
	}
}

const absenceRules = `
webhooks:
  - name: hook
    url: http://127.0.0.1:1/
rules:
  - name: heartbeat
    files: [/var/log/app.log]
    absent: 'heartbeat OK'
    for: 10m
    webhooks: [hook]
`

func TestAbsenceRule(t *testing.T) {
	e, got, clk := newTestEngine(t, absenceRules)
	const f = "/var/log/app.log"

	// Seen regularly: never fires.
	for i := 0; i < 3; i++ {
		clk.t = clk.t.Add(5 * time.Minute)
		e.process(f, []byte("12:00 heartbeat OK"))
		e.sweep()
	}
	if len(*got) != 0 {
		t.Fatalf("fired while the line was seen: %+v", *got)
	}

	// Missing for 10 minutes: fires once.
	clk.t = clk.t.Add(10 * time.Minute)
	e.sweep()
	e.sweep()
	if len(*got) != 1 || (*got)[0].Kind != "absent" {
		t.Fatalf("alerts = %+v, want one absent alert", *got)
	}
	if !strings.Contains((*got)[0].Text, "no matching line") {
		t.Fatalf("text = %q", (*got)[0].Text)
	}

	// Seen again: one recovery alert; unrelated lines do nothing.
	e.process(f, []byte("something else"))
	e.process(f, []byte("12:30 heartbeat OK"))
	e.process(f, []byte("12:31 heartbeat OK"))
	if len(*got) != 2 || (*got)[1].Kind != "recovered" {
		t.Fatalf("alerts = %+v, want a recovery alert", *got)
	}
}

// At log_level debug every matching line is logged with what happened to
// it; at the default level nothing is.
func TestDebugLogsMatches(t *testing.T) {
	const src = `
webhooks:
  - name: h
    url: http://127.0.0.1:1/hook
rules:
  - name: deploy-failed
    files: [/var/log/app.log]
    pattern: 'Failed to deploy "(?P<app>[^"]+)"'
    exclude: 'smoke-test'
    webhooks: [h]
    suppress: {window: 10m}
`
	const f = "/var/log/app.log"
	lines := []string{
		`ERROR Failed to deploy "billing"`,    // alert
		`ERROR Failed to deploy "billing"`,    // suppressed
		`ERROR Failed to deploy "smoke-test"`, // excluded
		`INFO deployed "shop"`,                // no match: not logged
	}
	run := func(level slog.Level) string {
		e, _, _ := newTestEngine(t, src)
		var out strings.Builder
		e.log = slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: level}))
		for _, l := range lines {
			e.process(f, []byte(l))
		}
		return out.String()
	}

	log := run(slog.LevelDebug)
	for _, want := range []string{
		`level=DEBUG msg="rule matched, sending alert" rule=deploy-failed file=/var/log/app.log line="ERROR Failed to deploy \"billing\"" groups=map[app:billing]`,
		`level=DEBUG msg="rule matched, alert suppressed" rule=deploy-failed file=/var/log/app.log line="ERROR Failed to deploy \"billing\"" groups=map[app:billing] suppressed_in_window=1`,
		`level=DEBUG msg="rule matched, but the line is excluded" rule=deploy-failed file=/var/log/app.log line="ERROR Failed to deploy \"smoke-test\""`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("debug log lacks\n  %s\ngot:\n%s", want, log)
		}
	}
	if strings.Contains(log, "shop") {
		t.Errorf("a line no rule matched was logged:\n%s", log)
	}
	if strings.Count(log, "\n") != 3 {
		t.Errorf("want 3 log lines, got:\n%s", log)
	}

	if log := run(slog.LevelInfo); log != "" {
		t.Errorf("matches logged at info level:\n%s", log)
	}
}
