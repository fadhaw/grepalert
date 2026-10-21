package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

func TestSimulate(t *testing.T) {
	c, err := rules.ParseWith([]byte(`
webhooks:
  - name: chat
    url: ${CHAT_URL_NOT_SET}
    template: '{"text": {{ json (printf "%s, %s is suspended" (title .Severity) .Groups.ds) }}}'
  - name: raw
    url: http://127.0.0.1:1/raw
rules:
  - name: suspended
    files: [/var/log/app.log]
    pattern: 'Datasource (?P<ds>\S+) is suspended because (?P<reason>.+)'
    exclude: 'maintenance'
    severity: critical
    webhooks: [chat, raw]
    suppress: {window: 1m, group_by: ds}
  - name: heartbeat
    files: [/var/log/app.log]
    absent: 'alive'
    for: 5m
    webhooks: [raw]
`), rules.Options{AllowUnresolvedEnv: true})
	if err != nil {
		t.Fatal(err)
	}
	res := Simulate(c, []string{
		"Datasource DS1 is suspended because pool exhausted",
		"all good",
		"Datasource DS1 is suspended because still exhausted", // same ds within 1m: suppressed
		"Datasource DS2 is suspended because disk full",
		"Datasource DS3 is suspended because maintenance", // excluded
	}, time.Second)

	if len(res.Lines) != 5 || len(res.Lines[1].Matches) != 0 {
		t.Fatalf("lines = %+v", res.Lines)
	}
	outcomes := []string{}
	for _, l := range res.Lines {
		for _, m := range l.Matches {
			outcomes = append(outcomes, m.Outcome)
		}
	}
	if got := strings.Join(outcomes, ","); got != "alert,suppressed,alert,excluded" {
		t.Errorf("outcomes = %s", got)
	}
	if g := res.Lines[0].Matches[0].Groups; g["ds"] != "DS1" || g["reason"] != "pool exhausted" {
		t.Errorf("groups = %v", g)
	}
	// Two alerts, then DS1's summary when its window closes.
	if len(res.Alerts) != 3 || res.Alerts[2].Kind != "summary" || res.Alerts[2].Suppressed != 1 {
		t.Fatalf("alerts = %+v", res.Alerts)
	}
	if d := res.Alerts[0].Deliveries; len(d) != 2 || d[0].Body != `{"text": "Critical, DS1 is suspended"}` || d[0].ContentType != "application/json" ||
		!strings.Contains(d[1].Body, `"rule":"suspended"`) {
		t.Errorf("deliveries = %+v", d)
	}
	if res.Alerts[2].Deliveries[0].Body != `{"text": "Critical, DS1 is suspended"}` {
		t.Errorf("summary body = %s", res.Alerts[2].Deliveries[0].Body)
	}
	if res.Lines[0].Matches[0].Alert != 0 || res.Lines[3].Matches[0].Alert != 1 || res.Alerts[1].Line != 4 {
		t.Errorf("alert links: %+v %+v", res.Lines[3].Matches, res.Alerts[1])
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "heartbeat") {
		t.Errorf("notes = %v", res.Notes)
	}
}
