package agent

import (
	"fmt"
	"time"

	"github.com/fadhaw/grepalert/internal/alert"
	"github.com/fadhaw/grepalert/internal/rules"
)

// Simulate runs sample log lines through a rule set with the real matching
// and suppression engine, and renders every alert the way each of its
// webhooks would receive it. Nothing is sent. It backs the dashboard's rule
// playground.
//
// Lines are treated as arriving every `every` (suppression windows depend on
// time); when they are done, open windows are closed so their summaries show
// too. Rules are applied to every line regardless of their files, and
// absence rules are not simulated.

// SimMatch is one rule matching one line.
type SimMatch struct {
	Rule   string            `json:"rule"`
	Groups map[string]string `json:"groups,omitempty"`
	// Outcome is "alert" (sent), "suppressed" (inside a suppression window)
	// or "excluded" (the exclude pattern matched too).
	Outcome string `json:"outcome"`
	Alert   int    `json:"alert"` // index into SimResult.Alerts, or -1
}

type SimLine struct {
	N       int        `json:"n"` // 1-based
	Line    string     `json:"line"`
	Matches []SimMatch `json:"matches,omitempty"`
}

// SimDelivery is what one webhook would receive.
type SimDelivery struct {
	Webhook     string `json:"webhook"`
	Method      string `json:"method"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
	Error       string `json:"error,omitempty"`
}

type SimAlert struct {
	Kind       string            `json:"kind"`
	Rule       string            `json:"rule"`
	Line       int               `json:"line"` // the line that raised it; 0 for summaries
	At         string            `json:"at"`   // simulated time since the first line, e.g. "+12s"
	Text       string            `json:"text"`
	Groups     map[string]string `json:"groups,omitempty"`
	Suppressed int               `json:"suppressed,omitempty"`
	Deliveries []SimDelivery     `json:"deliveries"`
}

type SimResult struct {
	Lines  []SimLine  `json:"lines"`
	Alerts []SimAlert `json:"alerts"`
	Notes  []string   `json:"notes,omitempty"`
}

// MaxSimLines bounds a simulation's input.
const MaxSimLines = 5000

func Simulate(c *rules.Compiled, lines []string, every time.Duration) SimResult {
	res := SimResult{Lines: make([]SimLine, 0, len(lines)), Alerts: []SimAlert{}}
	if len(lines) > MaxSimLines {
		res.Notes = append(res.Notes, fmt.Sprintf("only the first %d lines were used", MaxSimLines))
		lines = lines[:MaxSimLines]
	}
	if every < 0 {
		every = 0
	}

	// Matching rules only; absence rules need real time to pass.
	live := &rules.Compiled{Raw: c.Raw, Hash: c.Hash, Webhooks: c.Webhooks}
	var maxWindow time.Duration
	for _, r := range c.Rules {
		if r.Absence {
			res.Notes = append(res.Notes, fmt.Sprintf("rule %q is an absence rule; it alerts when a line stops appearing, which a sample cannot show", r.Name))
			continue
		}
		live.Rules = append(live.Rules, r)
		maxWindow = max(maxWindow, r.SuppressWindow())
	}

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock, cur := start, 0
	raised := map[string]int{} // rule -> alert index raised by the current line
	e := newEngine("playground", "playground", newRing(1), func(a Alert, r *rules.CompiledRule) {
		sa := SimAlert{Kind: a.Kind, Rule: a.Rule, At: "+" + a.Time.Sub(start).String(), Text: a.Text,
			Groups: a.Groups, Suppressed: a.Suppressed, Deliveries: []SimDelivery{}}
		if a.Kind == alert.KindMatch {
			sa.Line = cur
			raised[a.Rule] = len(res.Alerts)
		}
		for _, h := range r.Hooks {
			d := SimDelivery{Webhook: h.Name, Method: h.Method}
			body, ctype, err := alert.Render(a, alert.FromRule(h))
			if err != nil {
				d.Error = "template: " + err.Error()
			} else {
				d.Body, d.ContentType = string(body), ctype
			}
			sa.Deliveries = append(sa.Deliveries, d)
		}
		res.Alerts = append(res.Alerts, sa)
	})
	e.now = func() time.Time { return clock }
	const path = "sample.log"
	e.setSnapshot(&snapshot{rules: live, byFile: map[string][]*rules.CompiledRule{path: live.Rules}})

	for i, line := range lines {
		clock = start.Add(time.Duration(i) * every)
		e.sweep() // windows that closed before this line
		cur = i + 1
		clear(raised)
		b := []byte(line)
		e.process(path, b)

		sl := SimLine{N: i + 1, Line: line}
		for _, r := range live.Rules {
			m := r.Re.FindSubmatchIndex(b)
			if m == nil {
				continue
			}
			sm := SimMatch{Rule: r.Name, Groups: captures(r, b, m), Alert: -1}
			switch idx, ok := raised[r.Name]; {
			case r.ExcludeRe != nil && r.ExcludeRe.Match(b):
				sm.Outcome = "excluded"
			case ok:
				sm.Outcome, sm.Alert = "alert", idx
			default:
				sm.Outcome = "suppressed"
			}
			sl.Matches = append(sl.Matches, sm)
		}
		res.Lines = append(res.Lines, sl)
	}
	// Close the windows still open, so their summaries show.
	cur = 0
	clock = clock.Add(maxWindow + time.Second)
	e.sweep()
	return res
}
