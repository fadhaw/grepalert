package agent

import (
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/alert"
	"github.com/fadhaw/grepalert/internal/rules"
)

// A named capture group picks a value out of the line, and the webhook
// template builds the message from it.
func TestTemplateUsesCapturedValues(t *testing.T) {
	c, err := rules.Parse([]byte(`
webhooks:
  - name: chat
    url: http://127.0.0.1:1/hook
    template: '{"text": {{ json (printf "%s, %s is suspended" (title .Severity) .Groups.datasource) }}}'
rules:
  - name: datasource-suspended
    files: [/var/log/app.log]
    pattern: 'Datasource (?P<datasource>\S+) is suspended because (?P<reason>.+)'
    severity: critical
    webhooks: [chat]
    suppress: {window: 1m, group_by: datasource}
`))
	if err != nil {
		t.Fatal(err)
	}
	var got []alert.Alert
	e := newEngine("a1", "h1", newRing(10), func(a Alert, _ *rules.CompiledRule) { got = append(got, a) })
	e.setSnapshot(&snapshot{rules: c, byFile: map[string][]*rules.CompiledRule{"/var/log/app.log": c.Rules}})
	e.process("/var/log/app.log", []byte("2026-10-14 10:00:01 Datasource DS1 is suspended because the pool is exhausted"))
	if len(got) != 1 {
		t.Fatalf("alerts = %d", len(got))
	}
	body, ctype, err := alert.Render(got[0], alert.FromRule(c.Rules[0].Hooks[0]))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"text": "Critical, DS1 is suspended"}`; string(body) != want || ctype != "application/json" {
		t.Fatalf("body = %s (%s), want %s", body, ctype, want)
	}
	if got[0].Groups["reason"] != "the pool is exhausted" {
		t.Errorf("groups = %v", got[0].Groups)
	}

	// The summary sent when the suppression window closes renders the same way.
	now := e.now()
	e.process("/var/log/app.log", []byte("Datasource DS1 is suspended because still exhausted"))
	e.now = func() time.Time { return now.Add(2 * time.Minute) }
	e.sweep()
	if len(got) != 2 || got[1].Kind != alert.KindSummary {
		t.Fatalf("alerts = %+v", got)
	}
	if body, _, _ := alert.Render(got[1], alert.FromRule(c.Rules[0].Hooks[0])); string(body) != `{"text": "Critical, DS1 is suspended"}` {
		t.Errorf("summary body = %s", body)
	}
}
