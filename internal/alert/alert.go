// Package alert defines the alert sent to webhooks and the bounded webhook
// sender. Agents use it to deliver directly; the dashboard uses it to deliver
// fleet-level (deduplicated) alerts.
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

// Kinds of alert.
const (
	KindMatch        = "match"         // a rule matched a line
	KindSummary      = "summary"       // an agent's suppression window closed
	KindAbsent       = "absent"        // an absence rule's line has not been seen for its duration
	KindRecovered    = "recovered"     // the line of a firing absence rule was seen again
	KindFleetSummary = "fleet_summary" // a group's fleet window closed with suppressed matches
	KindAgentDown    = "agent_down"    // the dashboard lost contact with an agent
	KindAgentUp      = "agent_up"      // an agent that was down is back
	KindRollout      = "rollout"       // a staged rollout of a group's rules was halted
)

// Alert is what gets delivered to a webhook. Webhook templates render it.
type Alert struct {
	// ID identifies one delivered alert (set by the dashboard); receivers can
	// use it to drop duplicates.
	ID          string            `json:"id,omitempty"`
	Kind        string            `json:"kind"`
	Agent       string            `json:"agent"`
	Host        string            `json:"host"`
	Group       string            `json:"group,omitempty"`
	Rule        string            `json:"rule"`
	Description string            `json:"description,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	File        string            `json:"file"`
	Line        string            `json:"line"`
	Groups      map[string]string `json:"groups,omitempty"`
	GroupKey    string            `json:"group_key,omitempty"`
	Time        time.Time         `json:"time"`
	// Suppressed is how many matches were swallowed by suppression (per agent,
	// or across the fleet for fleet alerts).
	Suppressed int `json:"suppressed"`
	// Hosts lists the agents a fleet alert covers; HostCount may exceed
	// len(Hosts) when the list is shortened.
	Hosts     []string `json:"hosts,omitempty"`
	HostCount int      `json:"host_count,omitempty"`
	// Via is "dashboard" for alerts the dashboard delivered and "agent" for
	// alerts an agent delivered itself (direct agents, or fallback).
	Via string `json:"via,omitempty"`
	// Text is a ready-made human readable message.
	Text string `json:"text"`
}

// Hook is a resolved webhook destination. Agents resolve ${VAR} references
// before handing hooks to the dashboard, which may not have those variables.
type Hook struct {
	Name     string            `json:"name"`
	URL      string            `json:"url"`
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Template string            `json:"template,omitempty"`
	Timeout  time.Duration     `json:"timeout,omitempty"`

	tmpl *template.Template
}

// FromRule converts a compiled rule webhook, reusing its parsed template.
func FromRule(w *rules.CompiledWebhook) *Hook {
	return &Hook{Name: w.Name, URL: w.URL, Method: w.Method, Headers: w.Headers,
		Template: w.Template, Timeout: w.Timeout.D(), tmpl: w.Tmpl}
}

// Compile parses the template of a hook received over the wire.
func (h *Hook) Compile() error {
	if h.Method == "" {
		h.Method = "POST"
	}
	if h.Timeout <= 0 {
		h.Timeout = 10 * time.Second
	}
	if h.Template != "" && h.tmpl == nil {
		t, err := template.New(h.Name).Funcs(rules.TemplateFuncs).Parse(h.Template)
		if err != nil {
			return fmt.Errorf("webhook %q: template: %w", h.Name, err)
		}
		h.tmpl = t
	}
	return nil
}

// Render produces the request body and content type for a.
func Render(a Alert, h *Hook) ([]byte, string, error) {
	if h.tmpl == nil {
		b, err := json.Marshal(a)
		return b, "application/json", err
	}
	var buf bytes.Buffer
	if err := h.tmpl.Execute(&buf, a); err != nil {
		return nil, "", err
	}
	ctype := "text/plain; charset=utf-8"
	if t := bytes.TrimSpace(buf.Bytes()); len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		ctype = "application/json"
	}
	return buf.Bytes(), ctype, nil
}

// HostList formats hosts as "a, b, c +N".
func HostList(hosts []string, total int) string {
	s := strings.Join(hosts, ", ")
	if extra := total - len(hosts); extra > 0 {
		s += fmt.Sprintf(" +%d", extra)
	}
	return s
}

// FormatText builds the human readable Text of an alert.
func FormatText(a Alert) string {
	var b strings.Builder
	sev := ""
	if a.Severity != "" {
		sev = strings.ToUpper(a.Severity) + " "
	}
	who := a.Agent
	if a.Group != "" && a.HostCount > 1 {
		who = a.Group
	}
	key := ""
	if a.GroupKey != "" {
		key = " (" + a.GroupKey + ")"
	}
	switch a.Kind {
	case KindSummary:
		fmt.Fprintf(&b, "%s[%s] %s%s: %d more matches were suppressed. Last: %s", sev, a.Agent, a.Rule, key, a.Suppressed, a.Line)
	case KindFleetSummary:
		fmt.Fprintf(&b, "%s[%s] %s%s: %d more matches on %d hosts were suppressed (%s). Last: %s",
			sev, who, a.Rule, key, a.Suppressed, a.HostCount, HostList(a.Hosts, a.HostCount), a.Line)
	case KindAbsent:
		fmt.Fprintf(&b, "%s[%s] %s: no matching line in %s", sev, who, a.Rule, a.Line)
		if a.HostCount > 1 {
			fmt.Fprintf(&b, " on %d hosts (%s)", a.HostCount, HostList(a.Hosts, a.HostCount))
		}
	case KindRecovered:
		fmt.Fprintf(&b, "[%s] %s recovered: the expected line was seen again", a.Agent, a.Rule)
	case KindRollout:
		fmt.Fprintf(&b, "%s[%s] staged rollout %s", sev, a.Group, a.Line)
	case KindAgentDown, KindAgentUp:
		if a.Group != "" {
			fmt.Fprintf(&b, "[%s] ", a.Group)
		}
		state := "down"
		if a.Kind == KindAgentUp {
			state = "back"
		}
		fmt.Fprintf(&b, "agent %s is %s: %s", a.Agent, state, a.Line)
	default:
		if a.HostCount > 1 {
			fmt.Fprintf(&b, "%s[%s] %s%s on %d hosts (%s): %s", sev, who, a.Rule, key, a.HostCount, HostList(a.Hosts, a.HostCount), a.Line)
		} else {
			fmt.Fprintf(&b, "%s[%s] %s matched in %s: %s", sev, a.Agent, a.Rule, a.File, a.Line)
		}
		if a.Suppressed > 0 {
			fmt.Fprintf(&b, " (+%d suppressed in previous window)", a.Suppressed)
		}
	}
	return b.String()
}
