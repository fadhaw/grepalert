package dashboard

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fadhaw/grepalert/internal/agent"
	"github.com/fadhaw/grepalert/internal/rules"
)

// handlePlayground runs sample log lines through draft rules and shows what
// each rule captures and what each webhook would receive. It is stateless:
// nothing is saved, sent, or pushed to agents, so any signed-in user may use it.
func (s *Server) handlePlayground(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rules string `json:"rules"`
		Lines string `json:"lines"`
		Every string `json:"every"` // time between lines, e.g. "1s"
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Rules) > maxRulesSize {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("rules are larger than %d bytes", maxRulesSize))
		return
	}
	every := time.Second
	if req.Every != "" {
		d, err := time.ParseDuration(req.Every)
		if err != nil || d < 0 || d > 24*time.Hour {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("every must be a duration like 1s or 30s"))
			return
		}
		every = d
	}
	// ${VAR}s in webhook URLs live in the agents' environments, not here.
	c, err := rules.ParseWith([]byte(req.Rules), rules.Options{AllowUnresolvedEnv: true})
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	text := strings.TrimRight(strings.ReplaceAll(req.Lines, "\r\n", "\n"), "\n")
	var lines []string
	if text != "" {
		lines = strings.Split(text, "\n")
	}
	type ruleInfo struct {
		Name    string   `json:"name"`
		Pattern string   `json:"pattern"`
		Groups  []string `json:"groups,omitempty"` // named captures
		Absence bool     `json:"absence,omitempty"`
	}
	info := make([]ruleInfo, 0, len(c.Rules))
	for _, cr := range c.Rules {
		ri := ruleInfo{Name: cr.Name, Pattern: cr.Re.String(), Absence: cr.Absence}
		for _, n := range cr.Re.SubexpNames() {
			if n != "" {
				ri.Groups = append(ri.Groups, n)
			}
		}
		info = append(info, ri)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": info, "result": agent.Simulate(c, lines, every)})
}
