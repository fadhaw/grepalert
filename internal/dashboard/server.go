// Package dashboard implements the grepalert web dashboard: connect agents,
// organise them into groups that share a rule set (edited here or synced from
// GitHub/GitLab), and monitor them.
package dashboard

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

const maxProxyBody = 2 << 20

type Server struct {
	cfg   Config
	log   *slog.Logger
	store *Store
	git   *http.Client

	clMu    sync.Mutex
	clients map[string]*agentClient // keyed by agent name

	stMu        sync.Mutex
	groupStates map[string]*groupState

	tunMu   sync.Mutex
	tunnels map[string]*tunnel // keyed by connected agent ID

	fleet *fleet // fleet dedupe, silences, agent-down alerts, history

	audit    *auditLog
	limiter  *loginLimiter
	oidcInit oidcOnce

	stopping     chan struct{} // closed by Shutdown to release held polls
	stoppingOnce sync.Once
}

type agentClient struct {
	rec  AgentRecord
	http *http.Client
}

func New(cfg Config, store *Store, log *slog.Logger) *Server {
	cfg.setDefaults()
	s := &Server{
		cfg:         cfg,
		log:         log,
		store:       store,
		git:         &http.Client{Timeout: 30 * time.Second},
		clients:     map[string]*agentClient{},
		groupStates: map[string]*groupState{},
		tunnels:     map[string]*tunnel{},
		stopping:    make(chan struct{}),
	}
	s.fleet = newFleet(s)
	s.audit = openAudit(cfg.AuditFile, log)
	s.limiter = &loginLimiter{hits: map[string][]time.Time{}}
	return s
}

// RunFleet delivers fleet alerts and watches for agents going down, until ctx
// is done.
func (s *Server) RunFleet(ctx context.Context) { s.fleet.Run(ctx) }

// tunnelBase is the placeholder URL for connected agents; requests to it are
// carried by tunnelTransport, never dialed.
const tunnelBase = "http://agent.tunnel"

// client returns a cached HTTP client for the agent, rebuilt when its
// connection settings change. Connected agents are reached through their
// poll tunnel, direct agents over HTTP(S).
func (s *Server) client(a AgentRecord) *agentClient {
	s.clMu.Lock()
	defer s.clMu.Unlock()
	if c, ok := s.clients[a.Name]; ok && c.rec.URL == a.URL && c.rec.Token == a.Token &&
		c.rec.InsecureSkipVerify == a.InsecureSkipVerify && c.rec.ID == a.ID && c.rec.Mode == a.Mode {
		return c
	}
	var c *agentClient
	if a.Connected() {
		rec := a
		rec.URL, rec.Token = tunnelBase, ""
		c = &agentClient{rec: rec, http: &http.Client{Transport: &tunnelTransport{s: s, id: a.ID}, Timeout: 15 * time.Second}}
	} else {
		c = newAgentClient(a)
	}
	s.clients[a.Name] = c
	return c
}

func newAgentClient(a AgentRecord) *agentClient {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 2
	if a.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &agentClient{rec: a, http: &http.Client{Transport: tr, Timeout: 15 * time.Second}}
}

// call performs a request against an agent's API.
func (c *agentClient) call(ctx context.Context, method, path string, body io.Reader, hdr http.Header) (*http.Response, error) {
	return c.do(ctx, c.http, method, path, body, hdr)
}

// callLong is call for slow requests (dry runs): only ctx bounds it.
func (c *agentClient) callLong(ctx context.Context, method, path string, body io.Reader, hdr http.Header) (*http.Response, error) {
	hc := *c.http
	hc.Timeout = 0
	return c.do(ctx, &hc, method, path, body, hdr)
}

func (c *agentClient) do(ctx context.Context, hc *http.Client, method, path string, body io.Reader, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.rec.URL, "/")+path, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if tok := rules.ExpandEnv(c.rec.Token); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return hc.Do(req)
}

// status fetches an agent's status JSON.
func (c *agentClient) status(ctx context.Context) (json.RawMessage, error) {
	resp, err := c.call(ctx, http.MethodGet, "/api/v1/status", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody))
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errors.New("the agent rejected the token (HTTP 401)")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	case !json.Valid(body):
		return nil, errors.New("the URL answered, but not like a grepalert agent")
	}
	return body, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", uiHandler())
	// Liveness for load balancers, Kubernetes and the Docker health check (no auth).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// Sign-in (public paths are listed in isPublic).
	mux.HandleFunc("GET /api/auth/config", s.handleAuthConfig)
	mux.HandleFunc("POST /auth/local", s.handleLocalLogin)
	mux.HandleFunc("GET /auth/oidc", s.handleOIDCStart)
	mux.HandleFunc("GET /auth/callback", s.handleOIDCCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.handleMe)

	// Access policy for every route, in one place. Any signed-in user may
	// call the routes without a guard; they filter what they return.
	admin := func(h http.HandlerFunc) http.HandlerFunc { return s.guard(RoleAdmin, noScope, h) }
	onAgent := func(role Role, h http.HandlerFunc) http.HandlerFunc { return s.guard(role, s.agentScope, h) }
	onGroup := func(role Role, h http.HandlerFunc) http.HandlerFunc { return s.guard(role, groupScope, h) }

	mux.HandleFunc("GET /api/overview", s.handleOverview)

	mux.HandleFunc("POST /api/agents/test", admin(s.handleTestConnection))
	mux.HandleFunc("POST /api/agents", admin(s.handleAddAgent))
	mux.HandleFunc("PUT /api/agents/{name}", admin(s.handleUpdateAgent))
	mux.HandleFunc("DELETE /api/agents/{name}", admin(s.handleDeleteAgent))
	mux.HandleFunc("POST /api/agents/{name}/revoke", admin(s.handleSetRevoked(true)))
	mux.HandleFunc("POST /api/agents/{name}/allow", admin(s.handleSetRevoked(false)))
	mux.HandleFunc("GET /api/agents/{name}/status", onAgent(RoleViewer, s.proxy("GET", "/api/v1/status")))
	mux.HandleFunc("GET /api/agents/{name}/rules", onAgent(RoleViewer, s.proxy("GET", "/api/v1/rules")))
	mux.HandleFunc("GET /api/agents/{name}/events", onAgent(RoleViewer, s.proxy("GET", "/api/v1/events")))
	mux.HandleFunc("POST /api/agents/{name}/test", onAgent(RoleViewer, s.proxy("POST", "/api/v1/test")))
	mux.HandleFunc("PUT /api/agents/{name}/rules", onAgent(RoleEditor, s.proxy("PUT", "/api/v1/rules")))
	mux.HandleFunc("POST /api/agents/{name}/validate", onAgent(RoleEditor, s.proxy("POST", "/api/v1/rules/validate")))
	mux.HandleFunc("GET /api/agents/{name}/own-rules", onAgent(RoleViewer, s.proxy("GET", "/api/v1/rules/own")))
	mux.HandleFunc("POST /api/agents/{name}/own-rules/restore", onAgent(RoleEditor, s.handleRestoreOwnRules))
	mux.HandleFunc("GET /api/agents/{name}/local-rules", onAgent(RoleViewer, s.handleGetLocalRules))
	mux.HandleFunc("PUT /api/agents/{name}/local-rules", onAgent(RoleEditor, s.handlePutLocalRules))

	mux.HandleFunc("POST /api/groups", admin(s.handleAddGroup))
	mux.HandleFunc("PUT /api/groups/{name}", admin(s.handleUpdateGroup))
	mux.HandleFunc("DELETE /api/groups/{name}", admin(s.handleDeleteGroup))
	mux.HandleFunc("GET /api/groups/{name}/rules", onGroup(RoleViewer, s.handleGroupRules))
	mux.HandleFunc("GET /api/groups/{name}/preview", onGroup(RoleViewer, s.handlePreview))
	mux.HandleFunc("PUT /api/groups/{name}/rules", onGroup(RoleEditor, s.handleSetGroupRules))
	mux.HandleFunc("POST /api/groups/{name}/validate", onGroup(RoleEditor, s.handleValidate))
	mux.HandleFunc("POST /api/groups/{name}/sync", onGroup(RoleEditor, s.handleSyncGroup))
	mux.HandleFunc("POST /api/groups/{name}/dryrun", onGroup(RoleEditor, s.handleDryRun))
	mux.HandleFunc("GET /api/groups/{name}/versions", onGroup(RoleViewer, s.handleListVersions))
	mux.HandleFunc("GET /api/groups/{name}/versions/{hash}", onGroup(RoleViewer, s.handleGetVersion))
	mux.HandleFunc("POST /api/groups/{name}/rollback", onGroup(RoleEditor, s.handleRollback))
	mux.HandleFunc("POST /api/groups/{name}/rollout", onGroup(RoleEditor, s.handleRolloutAction))

	mux.HandleFunc("GET /api/tokens", admin(s.handleListTokens))
	mux.HandleFunc("POST /api/tokens", admin(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/tokens/{id}", admin(s.handleRevokeToken))

	mux.HandleFunc("POST /api/playground", s.handlePlayground) // any signed-in user: stateless, sends nothing
	mux.HandleFunc("GET /api/alerts", s.handleHistory)
	mux.HandleFunc("GET /api/silences", s.handleListSilences)
	mux.HandleFunc("POST /api/silences", s.handleAddSilence)           // editor of the silenced group, checked inside
	mux.HandleFunc("DELETE /api/silences/{id}", s.handleExpireSilence) // same
	mux.HandleFunc("GET /api/settings", admin(s.handleGetSettings))
	mux.HandleFunc("PUT /api/settings", admin(s.handlePutSettings))
	mux.HandleFunc("POST /api/settings/test-ops", admin(s.handleTestOps))

	mux.HandleFunc("GET /api/users", admin(s.handleListUsers))
	mux.HandleFunc("PUT /api/users/{name}", admin(s.handleSetUser))
	mux.HandleFunc("DELETE /api/users/{name}", admin(s.handleDeleteUser))
	mux.HandleFunc("GET /api/access", admin(s.handleListBindings))
	mux.HandleFunc("POST /api/access", admin(s.handleAddBinding))
	mux.HandleFunc("DELETE /api/access/{id}", admin(s.handleDeleteBinding))
	mux.HandleFunc("GET /api/audit", admin(s.handleAudit))
	mux.HandleFunc("GET /api/audit/export", admin(s.handleAuditExport))

	// Endpoints for connected agents. They authenticate with enrollment
	// tokens or agent credentials, not with the dashboard login.
	mux.HandleFunc("POST /agent/v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /agent/v1/poll", s.handlePoll)
	mux.HandleFunc("POST /agent/v1/respond", s.handleRespond)
	mux.HandleFunc("POST /agent/v1/alerts", s.handleAlerts)
	return s.auth(mux)
}

// guard runs h only if the caller has role in the scope scopeOf returns.
func (s *Server) guard(role Role, scopeOf func(*http.Request) string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.need(w, r, role, scopeOf(r)) {
			h(w, r)
		}
	}
}

func noScope(*http.Request) string      { return "" }
func groupScope(r *http.Request) string { return r.PathValue("name") }

// agentScope is the group of the agent in the path ("" if ungrouped or
// unknown; unknown agents then get a 404 from the handler).
func (s *Server) agentScope(r *http.Request) string {
	if a, ok := s.store.Agent(r.PathValue("name")); ok {
		return EffectiveGroup(a, s.store.Groups())
	}
	return ""
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxProxyBody)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
		return false
	}
	return true
}

// ---- overview ----

type agentView struct {
	Name string `json:"name"`
	Mode string `json:"mode"` // "direct" or "connected"
	URL  string `json:"url,omitempty"`
	// Group is the effective group; Assigned tells whether an admin chose it
	// (otherwise it came from a label selector).
	Group              string            `json:"group,omitempty"`
	Assigned           bool              `json:"assigned,omitempty"`
	HasToken           bool              `json:"has_token"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify,omitempty"`
	AddedAt            time.Time         `json:"added_at"`
	Labels             map[string]string `json:"labels,omitempty"`
	Hostname           string            `json:"hostname,omitempty"`
	EnrolledVia        string            `json:"enrolled_via,omitempty"`
	Revoked            bool              `json:"revoked,omitempty"`
	LastSeen           time.Time         `json:"last_seen,omitempty"`
	DownSince          time.Time         `json:"down_since,omitempty"` // set once an agent-down alert went out
	Online             bool              `json:"online"`
	Error              string            `json:"error,omitempty"`
	Status             json.RawMessage   `json:"status,omitempty"`
}

type gitView struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url,omitempty"`
	Repo     string `json:"repo,omitempty"`
	Ref      string `json:"ref,omitempty"`
	Path     string `json:"path"`
	Interval string `json:"interval,omitempty"`
	HasToken bool   `json:"has_token"`
}

type groupView struct {
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Source         string            `json:"source"`
	Git            *gitView          `json:"git,omitempty"`
	Selector       map[string]string `json:"selector,omitempty"`
	Fleet          FleetSettings     `json:"fleet"`
	OpsWebhookURL  string            `json:"ops_webhook_url,omitempty"`
	RulesHash      string            `json:"rules_hash,omitempty"`
	RulesUpdatedAt time.Time         `json:"rules_updated_at"`
	Members        []string          `json:"members"`
	State          groupState        `json:"state"`
	Rollout        RolloutSettings   `json:"rollout"`
	RolloutState   *Rollout          `json:"rollout_state,omitempty"`
	Canaries       []string          `json:"canaries,omitempty"` // members on the new version during a rollout
	GitPaused      string            `json:"git_paused,omitempty"`
}

func (s *Server) groupView(g GroupRecord) groupView {
	v := groupView{Name: g.Name, Description: g.Description, Source: g.Source, Selector: g.Selector, Fleet: g.Fleet, OpsWebhookURL: g.OpsWebhookURL, RulesHash: g.RulesHash,
		RulesUpdatedAt: g.RulesUpdatedAt, Members: []string{}, State: s.snapshotState(g.Name),
		Rollout: g.Rollout, RolloutState: g.RolloutState, GitPaused: g.GitPaused}
	if g.Git != nil {
		v.Git = &gitView{Provider: g.Git.Provider, BaseURL: g.Git.BaseURL, Repo: g.Git.Repo, Ref: g.Git.Ref,
			Path: g.Git.Path, Interval: g.Git.Interval, HasToken: g.Git.Token != ""}
	}
	members := s.store.Members(g.Name)
	for _, a := range members {
		v.Members = append(v.Members, a.Name)
	}
	if ro := g.RolloutState; ro != nil && ro.Status == "running" {
		for name := range canaries(ro, g.Rollout.stages(), members) {
			v.Canaries = append(v.Canaries, name)
		}
		sort.Strings(v.Canaries)
	}
	return v
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	recs, groups, down := s.store.Agents(), s.store.Groups(), s.fleet.downStates()
	// Only what the caller may see: agents and groups in scope of their roles.
	perms := authOf(r).perms
	visible := recs[:0]
	for _, a := range recs {
		if perms.Can(RoleViewer, EffectiveGroup(a, groups)) {
			visible = append(visible, a)
		}
	}
	recs = visible
	out := struct {
		Agents []agentView `json:"agents"`
		Groups []groupView `json:"groups"`
	}{Agents: make([]agentView, len(recs)), Groups: []groupView{}}

	var wg sync.WaitGroup
	for i, a := range recs {
		wg.Add(1)
		go func(i int, a AgentRecord) {
			defer wg.Done()
			v := agentView{Name: a.Name, Mode: "direct", URL: a.URL, Group: EffectiveGroup(a, groups), Assigned: a.Group != "",
				HasToken: a.Token != "", InsecureSkipVerify: a.InsecureSkipVerify, AddedAt: a.AddedAt}
			v.DownSince = down[a.Name]
			if a.Connected() {
				v.Mode, v.URL, v.Labels, v.Hostname, v.EnrolledVia = "connected", "", a.Labels, a.Hostname, a.EnrolledVia
				v.Revoked, v.LastSeen = a.Revoked, s.lastSeenAt(a.ID)
				if a.Revoked {
					v.Group, v.Error = "", "access revoked"
					out.Agents[i] = v
					return
				}
			}
			st, err := s.client(a).status(ctx)
			if err != nil {
				v.Error = err.Error()
			} else {
				v.Online, v.Status = true, st
			}
			out.Agents[i] = v
		}(i, a)
	}
	wg.Wait()
	for _, g := range groups {
		if !perms.Can(RoleViewer, g.Name) {
			continue
		}
		out.Groups = append(out.Groups, s.groupView(g))
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- agents ----

type agentRequest struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	Token              string `json:"token"`
	Group              string `json:"group"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	// Force saves the agent even if it cannot be reached right now.
	Force bool `json:"force"`
}

func (req *agentRequest) normalize() error {
	req.Name = strings.TrimSpace(req.Name)
	req.URL = strings.TrimSuffix(strings.TrimSpace(req.URL), "/")
	if req.URL == "" {
		return errors.New("agent URL is required")
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		req.URL = "http://" + req.URL
	}
	return nil
}

// probe checks that the agent answers, returning its reported name.
func probe(ctx context.Context, rec AgentRecord) (string, json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := newAgentClient(rec).status(ctx)
	if err != nil {
		return "", nil, err
	}
	var info struct {
		Name string `json:"name"`
	}
	json.Unmarshal(st, &info)
	return info.Name, st, nil
}

func (s *Server) handleTestConnection(w http.ResponseWriter, r *http.Request) {
	var req agentRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := req.normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rec := AgentRecord{URL: req.URL, Token: req.Token, InsecureSkipVerify: req.InsecureSkipVerify}
	if req.Token == "" && req.Name != "" { // editing: reuse the stored token
		if old, ok := s.store.Agent(req.Name); ok {
			rec.Token = old.Token
		}
	}
	_, st, err := probe(r.Context(), rec)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": st})
}

func (s *Server) handleAddAgent(w http.ResponseWriter, r *http.Request) {
	var req agentRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := req.normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	rec := AgentRecord{Name: req.Name, URL: req.URL, Token: req.Token, Group: req.Group, InsecureSkipVerify: req.InsecureSkipVerify}
	reported, _, err := probe(r.Context(), rec)
	if err != nil && !req.Force {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "cannot connect: " + err.Error(), "unreachable": true})
		return
	}
	if rec.Name == "" {
		rec.Name = reported
	}
	if rec.Name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("enter a name (the agent could not be asked for one)"))
		return
	}
	if err := s.store.AddAgent(rec); err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	s.log.Info("agent added", "agent", rec.Name, "url", rec.URL, "group", rec.Group)
	s.audit.record(r, "agent.add", rec.Name, rec.Group, "ok", "url "+rec.URL, "")
	writeJSON(w, http.StatusOK, map[string]any{"name": rec.Name, "push": s.pushToNewMember(r.Context(), rec)})
}

func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	old, ok := s.store.Agent(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("agent not found"))
		return
	}
	var req agentRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !old.Connected() {
		if err := req.normalize(); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	groups := s.store.Groups()
	rec, err := s.store.UpdateAgent(old.Name, func(a *AgentRecord) error {
		a.Group = req.Group // for connected agents "" means "by labels"
		if !a.Connected() {
			a.URL, a.InsecureSkipVerify = req.URL, req.InsecureSkipVerify
			if req.Token != "" { // empty keeps the stored token
				a.Token = req.Token
			}
		}
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var push *PushResult
	if g := EffectiveGroup(rec, groups); g != "" && (g != EffectiveGroup(old, groups) || rec.URL != old.URL) {
		push = s.pushToNewMember(r.Context(), rec)
	}
	s.audit.record(r, "agent.update", rec.Name, EffectiveGroup(rec, groups), "ok", fmt.Sprintf("group %q → %q", old.Group, rec.Group),
		lineDiff(agentSettingsText(old), agentSettingsText(rec)))
	writeJSON(w, http.StatusOK, map[string]any{"name": rec.Name, "push": push})
}

// handleSetRevoked blocks (or re-allows) a connected agent. A revoked agent's
// polls are refused, so it gets no rules or requests until allowed again.
func (s *Server) handleSetRevoked(revoked bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, err := s.store.UpdateAgent(r.PathValue("name"), func(a *AgentRecord) error {
			if !a.Connected() {
				return errors.New("only agents that connect to the dashboard can be revoked; remove direct agents instead")
			}
			a.Revoked = revoked
			return nil
		})
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		s.log.Info("agent access changed", "agent", rec.Name, "revoked", revoked)
		action := "agent.allow"
		if revoked {
			action = "agent.revoke"
		}
		s.audit.record(r, action, rec.Name, EffectiveGroup(rec, s.store.Groups()), "ok", "", "")
		if revoked {
			s.wakeTunnel(rec.ID)
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": rec.Name, "revoked": revoked})
	}
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	type tokenView struct {
		EnrollmentToken
		Hash    string `json:"hash,omitempty"` // never sent
		Expired bool   `json:"expired"`
	}
	out := []tokenView{}
	for _, t := range s.store.Tokens() {
		out = append(out, tokenView{EnrollmentToken: t, Expired: !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out, "config_token": s.cfg.EnrollmentToken != ""})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		TTL  string `json:"ttl"` // e.g. "24h"; empty = never expires
	}
	if !readJSON(w, r, &req) {
		return
	}
	var ttl time.Duration
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d <= 0 {
			writeErr(w, http.StatusBadRequest, errors.New("invalid expiry"))
			return
		}
		ttl = d
	}
	t, raw, err := s.store.CreateToken(strings.TrimSpace(req.Name), ttl)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.log.Info("enrollment token created", "name", t.Name, "expires", t.ExpiresAt)
	s.audit.record(r, "token.create", t.Name, "", "ok", "prefix "+t.Prefix+", expires "+fmtTime(t.ExpiresAt), "")
	writeJSON(w, http.StatusOK, map[string]any{"id": t.ID, "name": t.Name, "token": raw, "expires_at": t.ExpiresAt})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeToken(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	s.audit.record(r, "token.revoke", r.PathValue("id"), "", "ok", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"revoked": r.PathValue("id")})
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteAgent(name); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	s.clMu.Lock()
	delete(s.clients, name)
	s.clMu.Unlock()
	s.audit.record(r, "agent.remove", name, "", "ok", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

// proxy forwards a request to the agent's own API.
func (s *Server) proxy(method, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, ok := s.store.Agent(r.PathValue("name"))
		if !ok {
			writeErr(w, http.StatusNotFound, errors.New("unknown agent"))
			return
		}
		if g := EffectiveGroup(rec, s.store.Groups()); method == http.MethodPut && g != "" {
			writeErr(w, http.StatusConflict, fmt.Errorf("this agent's rules are managed by group %q; edit the group's rules instead", g))
			return
		}
		p := path
		if q := r.URL.RawQuery; q != "" {
			p += "?" + q
		}
		hdr := http.Header{}
		var body io.Reader
		if method != http.MethodGet {
			body = http.MaxBytesReader(w, r.Body, maxProxyBody)
			hdr.Set("Content-Type", r.Header.Get("Content-Type"))
			hdr.Set("X-Rules-Origin", "dashboard")
		}
		// Rule edits are audited with a diff, so read the new rules and fetch
		// the current ones first.
		var before string
		var sent []byte
		if method == http.MethodPut {
			raw, err := io.ReadAll(body)
			if err != nil {
				writeErr(w, http.StatusRequestEntityTooLarge, err)
				return
			}
			sent, body = raw, bytes.NewReader(raw)
			if old, err := s.client(rec).call(r.Context(), http.MethodGet, "/api/v1/rules", nil, nil); err == nil {
				b, _ := io.ReadAll(io.LimitReader(old.Body, maxProxyBody))
				old.Body.Close()
				before = string(b)
			}
		}
		resp, err := s.client(rec).call(r.Context(), method, p, body, hdr)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		if method == http.MethodPut {
			if resp.StatusCode < 300 {
				s.audit.record(r, "agent.rules.update", rec.Name, "", "ok", "", lineDiff(before, string(sent)))
			} else {
				s.audit.record(r, "agent.rules.update", rec.Name, "", "failed", fmt.Sprintf("agent answered HTTP %d", resp.StatusCode), "")
			}
		}
		defer resp.Body.Close()
		for _, h := range []string{"Content-Type", "X-Rules-Hash"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, io.LimitReader(resp.Body, maxProxyBody))
	}
}

// ---- groups ----

type groupRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Source      string            `json:"source"`
	Git         *GitSource        `json:"git"`
	Selector    map[string]string `json:"selector"`
	Fleet       FleetSettings     `json:"fleet"`
	OpsWebhook  string            `json:"ops_webhook_url"`
	Rollout     RolloutSettings   `json:"rollout"`
	// Rules optionally seeds a manual group's rule set on creation.
	Rules string `json:"rules"`
}

func (s *Server) handleAddGroup(w http.ResponseWriter, r *http.Request) {
	var req groupRequest
	if !readJSON(w, r, &req) {
		return
	}
	g := GroupRecord{Name: strings.TrimSpace(req.Name), Description: req.Description, Source: req.Source, Git: req.Git, Selector: req.Selector, Fleet: req.Fleet, OpsWebhookURL: strings.TrimSpace(req.OpsWebhook), Rollout: req.Rollout}
	if req.Rules != "" && req.Source == "manual" {
		if _, err := validateForDashboard([]byte(req.Rules)); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
		g.Rules = req.Rules
	}
	if err := s.store.AddGroup(g, authOf(r).id.User); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.log.Info("group created", "group", g.Name, "source", g.Source)
	s.audit.record(r, "group.create", g.Name, g.Name, "ok", "", lineDiff("", groupSettingsText(g)+"\n"+g.Rules))
	resp := map[string]any{"name": g.Name}
	// Fetch from git if needed, and push to members (including agents its
	// label selector just picked up).
	if err := s.syncGroup(r.Context(), g.Name, "created", g.Source == "git"); err != nil {
		resp["sync_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req groupRequest
	if !readJSON(w, r, &req) {
		return
	}
	before, _ := s.store.Group(name)
	g := GroupRecord{Name: name, Description: req.Description, Source: req.Source, Git: req.Git, Selector: req.Selector, Fleet: req.Fleet, OpsWebhookURL: strings.TrimSpace(req.OpsWebhook), Rollout: req.Rollout}
	if err := s.store.UpdateGroup(g); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	after, _ := s.store.Group(name)
	if ro := after.RolloutState; ro != nil && ro.Status == "running" && !after.Rollout.Enabled {
		after, _ = s.store.MutateGroup(name, func(g *GroupRecord) error {
			g.RolloutState.finish("done", "staged rollout turned off by "+authOf(r).id.User+"; every agent gets "+g.RulesHash)
			return nil
		})
	}
	s.audit.record(r, "group.update", name, name, "ok", "", lineDiff(groupSettingsText(before), groupSettingsText(after)))
	resp := map[string]any{"name": name}
	if err := s.syncGroup(r.Context(), name, "settings changed", g.Source == "git"); err != nil {
		resp["sync_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteGroup(name); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	s.stMu.Lock()
	delete(s.groupStates, name)
	s.stMu.Unlock()
	s.audit.record(r, "group.delete", name, name, "ok", "its agents are now ungrouped", "")
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

func (s *Server) handleGroupRules(w http.ResponseWriter, r *http.Request) {
	g, ok := s.store.Group(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("group not found"))
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("X-Rules-Hash", g.RulesHash)
	w.Write([]byte(g.Rules))
}

func (s *Server) handleSetGroupRules(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	g, ok := s.store.Group(name)
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("group not found"))
		return
	}
	if g.Source != "manual" {
		writeErr(w, http.StatusConflict, errors.New("this group's rules come from git; change them there and sync"))
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRulesSize))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	c, err := validateForDashboard(raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	actor := authOf(r).id.User
	if err := s.store.SetGroupRules(name, raw, RuleVersion{Author: actor, Source: "edited"}, func(ng *GroupRecord) {
		rolloutOnChange(ng, g.RulesHash, actor)
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.audit.record(r, "group.rules.update", name, name, "ok", fmt.Sprintf("version %s → %s", orNone(g.RulesHash), c.Hash), lineDiff(g.Rules, string(raw)))
	if err := s.syncGroup(r.Context(), name, "rules edited", false); err != nil && !errors.Is(err, errSyncing) {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	after, _ := s.store.Group(name)
	writeJSON(w, http.StatusOK, map[string]any{"hash": c.Hash, "rules": len(c.Rules), "state": s.snapshotState(name), "rollout": after.RolloutState})
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRulesSize))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	c, err := validateForDashboard(raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hash": c.Hash, "rules": len(c.Rules)})
}

func (s *Server) handleSyncGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.store.Group(name); !ok {
		writeErr(w, http.StatusNotFound, errors.New("group not found"))
		return
	}
	if g, _ := s.store.Group(name); g.GitPaused != "" {
		s.store.MutateGroup(name, func(g *GroupRecord) error { g.GitPaused = ""; return nil })
		s.audit.record(r, "group.git.resume", name, name, "ok", "following git again", "")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.syncGroup(ctx, name, "manual", true); err != nil {
		s.audit.record(r, "group.sync", name, name, "failed", err.Error(), "")
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	s.audit.record(r, "group.sync", name, name, "ok", "", "")
	writeJSON(w, http.StatusOK, s.snapshotState(name))
}

// handlePreview fetches a git group's rules without applying them.
func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	g, ok := s.store.Group(r.PathValue("name"))
	if !ok || g.Git == nil {
		writeErr(w, http.StatusNotFound, errors.New("not a git group"))
		return
	}
	raw, err := fetchSource(r.Context(), s.git, *g.Git)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("X-Rules-Hash", rules.Hash(raw))
	w.Write(raw)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// Shutdown releases held agent polls so an HTTP server shutdown does not wait
// for them. Agents simply reconnect to the next dashboard instance.
func (s *Server) Shutdown() {
	s.stoppingOnce.Do(func() { close(s.stopping) })
}

// ---- audit helpers ----

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// groupSettingsText renders a group's settings (not its rules, no secrets)
// for audit diffs.
func groupSettingsText(g GroupRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "description: %s\nsource: %s\n", g.Description, g.Source)
	if g.Git != nil {
		fmt.Fprintf(&b, "git: %s %s @ %s : %s (every %s, token %s)\n", g.Git.Provider, g.Git.Repo, g.Git.Ref, g.Git.Path,
			orNone(g.Git.Interval), map[bool]string{true: "set", false: "none"}[g.Git.Token != ""])
	}
	fmt.Fprintf(&b, "selector: %s\nfleet: disabled=%v wait=%s window=%s\nagent-down webhook: %s\n",
		labelsString(g.Selector), g.Fleet.Disabled, orNone(g.Fleet.Wait), orNone(g.Fleet.Window), maskURL(g.OpsWebhookURL))
	if g.Rollout.Enabled {
		fmt.Fprintf(&b, "staged rollout: stages=%s soak=%s max_increase=%g min_alerts=%d\n",
			strings.Join(g.Rollout.Stages, ","), g.Rollout.Soak, g.Rollout.MaxIncrease, g.Rollout.MinAlerts)
	} else {
		b.WriteString("staged rollout: off\n")
	}
	return b.String()
}

func agentSettingsText(a AgentRecord) string {
	return fmt.Sprintf("url: %s\ngroup: %s\ntoken: %s\ninsecure_skip_verify: %v\n", orNone(a.URL), orNone(a.Group),
		map[bool]string{true: "set", false: "none"}[a.Token != ""], a.InsecureSkipVerify)
}

func labelsString(l map[string]string) string {
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+l[k])
	}
	return orNone(strings.Join(parts, ","))
}

// maskURL keeps scheme and host only: webhook URLs often embed secrets.
func maskURL(u string) string {
	if u == "" || strings.HasPrefix(u, "${") {
		return orNone(u)
	}
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Scheme + "://" + p.Host + "/…"
	}
	return "(set)"
}
