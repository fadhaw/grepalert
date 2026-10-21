package agent

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

const maxRulesBody = 1 << 20

// Handler returns the agent's HTTP API, used by the dashboard.
//
//	GET  /healthz                 liveness (no auth)
//	GET  /api/v1/status           runtime status, files, rule stats, memory
//	GET  /api/v1/rules            current rules YAML (X-Rules-Hash header)
//	PUT  /api/v1/rules            replace rules (validated, persisted, hot-applied)
//	POST /api/v1/rules/validate   validate rules without applying
//	POST /api/v1/rules/dryrun     replay the last ?window= (default 1h, max 3h) of
//	                              the logs through the posted rules; nothing is sent
//	GET  /api/v1/rules/own        the agent's own rules from before a group replaced them
//	POST /api/v1/rules/own/restore  make those the active rules again
//	GET  /api/v1/rules/local      this machine's extra rules (JSON)
//	PUT  /api/v1/rules/local      replace them (empty body removes them)
//	GET  /api/v1/events?limit=N   recent events, newest first
//	POST /api/v1/test             {"line": "..."} → rules that would match
func (a *Agent) Handler() http.Handler { return a.auth(a.api()) }

// api is the unauthenticated API mux. The inbound listener wraps it with
// token auth; the dashboard tunnel calls it directly, because the tunnel
// connection is itself authenticated.
func (a *Agent) api() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.Status())
	})
	mux.HandleFunc("GET /api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		c := a.Rules()
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("X-Rules-Hash", c.Hash)
		w.Write(c.Raw)
	})
	mux.HandleFunc("PUT /api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRulesBody))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, err)
			return
		}
		origin := r.Header.Get("X-Rules-Origin")
		if origin == "" {
			origin = "api"
		}
		c, changed, err := a.ApplyRules(raw, origin)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"hash": c.Hash, "rules": len(c.Rules), "unchanged": !changed})
	})
	mux.HandleFunc("POST /api/v1/rules/validate", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRulesBody))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, err)
			return
		}
		c, err := rules.Parse(raw)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"hash": c.Hash, "rules": len(c.Rules)})
	})
	mux.HandleFunc("POST /api/v1/rules/dryrun", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRulesBody))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, err)
			return
		}
		window := time.Hour
		if v := r.URL.Query().Get("window"); v != "" {
			if window, err = time.ParseDuration(v); err != nil || window <= 0 || window > MaxDryRunWindow {
				writeErr(w, http.StatusBadRequest, fmt.Errorf("window must be a duration up to %s", MaxDryRunWindow))
				return
			}
		}
		// Webhook URLs are never called in a dry run, so unresolved ${VAR}s are fine.
		c, err := rules.ParseWith(raw, rules.Options{AllowUnresolvedEnv: true})
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		res, err := a.DryRun(r.Context(), c, window)
		if errors.Is(err, ErrDryRunBusy) {
			writeErr(w, http.StatusTooManyRequests, err)
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /api/v1/rules/own", func(w http.ResponseWriter, r *http.Request) {
		raw, ok := a.OwnRules()
		if !ok {
			writeErr(w, http.StatusNotFound, errors.New("no saved rules: no group has replaced this agent's own rules"))
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("X-Rules-Hash", rules.Hash(raw))
		w.Write(raw)
	})
	mux.HandleFunc("POST /api/v1/rules/own/restore", func(w http.ResponseWriter, r *http.Request) {
		c, err := a.RestoreOwnRules()
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"hash": c.Hash, "rules": len(c.Rules)})
	})
	mux.HandleFunc("GET /api/v1/rules/local", func(w http.ResponseWriter, r *http.Request) {
		raw, hash, rejected := a.LocalRules()
		writeJSON(w, http.StatusOK, map[string]any{"rules": string(raw), "hash": hash, "rejected": rejected,
			"enabled": a.cfg.LocalRulesFile != "off", "path": a.cfg.LocalRulesFile})
	})
	mux.HandleFunc("PUT /api/v1/rules/local", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRulesBody))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, err)
			return
		}
		origin := r.Header.Get("X-Rules-Origin")
		if origin == "" {
			origin = "api"
		}
		if err := a.ApplyLocalRules(raw, origin); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		_, hash, _ := a.LocalRules()
		writeJSON(w, http.StatusOK, map[string]any{"hash": hash, "rules": len(a.Active().Rules) - len(a.Rules().Rules)})
	})
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 100
		}
		writeJSON(w, http.StatusOK, a.Events(limit))
	})
	mux.HandleFunc("POST /api/v1/test", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Line string `json:"line"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"matched": a.TestLine(req.Line)})
	})
	return mux
}

func (a *Agent) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.Token != "" && r.URL.Path != "/healthz" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(a.cfg.Token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Server returns an http.Server for the agent API with conservative timeouts.
func (a *Agent) Server() *http.Server {
	return &http.Server{
		Addr:              a.cfg.Listen,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second, // a dry run may take a while
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
}

func (a *Agent) Config() Config { return a.cfg }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
