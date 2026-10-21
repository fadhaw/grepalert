package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

// PushResult is the outcome of making one agent run its group's rules.
type PushResult struct {
	OK     bool      `json:"ok"`
	Action string    `json:"action"` // "applied", "in sync" or "failed"
	Hash   string    `json:"hash,omitempty"`
	Error  string    `json:"error,omitempty"`
	Time   time.Time `json:"time"`
}

// groupState is runtime (not persisted) sync information for a group.
type groupState struct {
	Syncing   bool                  `json:"syncing"`
	LastSync  time.Time             `json:"last_sync"`
	LastFetch time.Time             `json:"last_fetch"`
	LastError string                `json:"last_error,omitempty"`
	Trigger   string                `json:"trigger,omitempty"`
	Results   map[string]PushResult `json:"results"`

	sample *rolloutSample // alert counters at the start of a rollout stage
}

// validateForDashboard checks rules without requiring the agents' env vars.
func validateForDashboard(raw []byte) (*rules.Compiled, error) {
	return rules.ParseWith(raw, rules.Options{AllowUnresolvedEnv: true})
}

func (s *Server) state(group string) *groupState {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	st := s.groupStates[group]
	if st == nil {
		st = &groupState{Results: map[string]PushResult{}}
		s.groupStates[group] = st
	}
	return st
}

// snapshotState returns a copy of a group's state that is safe to serialize.
func (s *Server) snapshotState(group string) groupState {
	st := s.state(group)
	s.stMu.Lock()
	defer s.stMu.Unlock()
	cp := *st
	cp.sample = nil
	cp.Results = make(map[string]PushResult, len(st.Results))
	for k, v := range st.Results {
		cp.Results[k] = v
	}
	return cp
}

// RunReconciler periodically fetches git groups whose interval elapsed and
// makes sure every member runs its group's rules. It blocks until ctx ends.
func (s *Server) RunReconciler(ctx context.Context) {
	t := time.NewTicker(s.cfg.ReconcileInterval.D())
	defer t.Stop()
	for {
		for _, g := range s.store.Groups() {
			fetch := false
			if g.Source == "git" && g.Git.Interval != "" && g.GitPaused == "" {
				every, _ := time.ParseDuration(g.Git.Interval)
				fetch = time.Since(s.snapshotState(g.Name).LastFetch) >= every
			}
			s.syncGroup(ctx, g.Name, "schedule", fetch)
		}
		s.advanceRollouts(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

var errSyncing = errors.New("a sync of this group is already running")

// syncGroup optionally fetches a git group's rules, then pushes the group's
// rules to every member that does not already run them.
func (s *Server) syncGroup(ctx context.Context, name, trigger string, fetch bool) error {
	st := s.state(name)
	s.stMu.Lock()
	if st.Syncing {
		s.stMu.Unlock()
		return errSyncing
	}
	st.Syncing = true
	s.stMu.Unlock()

	err := s.doSyncGroup(ctx, name, fetch, st)

	s.stMu.Lock()
	st.Syncing = false
	st.LastSync = time.Now()
	st.Trigger = trigger
	if err != nil {
		st.LastError = err.Error()
	} else {
		st.LastError = ""
	}
	s.stMu.Unlock()
	if err != nil && trigger != "schedule" {
		s.log.Error("group sync failed", "group", name, "err", err)
	}
	return err
}

func (s *Server) doSyncGroup(ctx context.Context, name string, fetch bool, st *groupState) error {
	g, ok := s.store.Group(name)
	if !ok {
		return fmt.Errorf("group %q not found", name)
	}
	if fetch && g.Source == "git" {
		raw, err := fetchSource(ctx, s.git, *g.Git)
		s.stMu.Lock()
		st.LastFetch = time.Now()
		s.stMu.Unlock()
		if err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
		if _, err := validateForDashboard(raw); err != nil {
			return fmt.Errorf("rules in git are invalid, not applied: %w", err)
		}
		if rules.Hash(raw) != g.RulesHash {
			prev := g.RulesHash
			if err := s.store.SetGroupRules(name, raw, RuleVersion{Author: "git", Source: "git", Note: gitSourceText(g.Git)}, func(ng *GroupRecord) {
				rolloutOnChange(ng, prev, "git")
			}); err != nil {
				return err
			}
			s.audit.system("git", "git", "group.rules.sync", name, name,
				fmt.Sprintf("version %s → %s from %s", orNone(g.RulesHash), rules.Hash(raw), gitSourceText(g.Git)), lineDiff(g.Rules, string(raw)))
			s.log.Info("group rules updated from git", "group", name, "hash", rules.Hash(raw))
		}
		g, _ = s.store.Group(name)
	}
	if g.RulesHash == "" {
		return nil // nothing to push yet
	}

	members := s.store.Members(name)
	results := make(map[string]PushResult, len(members))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, a := range members {
		wg.Add(1)
		go func(a AgentRecord) {
			defer wg.Done()
			raw, hash := s.targetFor(g, a, members)
			res := s.ensureRules(ctx, a, raw, hash, "group:"+name)
			mu.Lock()
			results[a.Name] = res
			mu.Unlock()
		}(a)
	}
	wg.Wait()

	s.stMu.Lock()
	st.Results = results
	s.stMu.Unlock()
	return nil
}

// ensureRules pushes raw to the agent unless it already runs that version.
func (s *Server) ensureRules(ctx context.Context, a AgentRecord, raw []byte, hash, origin string) PushResult {
	res := PushResult{Time: time.Now(), Hash: hash}
	c := s.client(a)

	// HEAD on the rules endpoint returns just the X-Rules-Hash header.
	if resp, err := c.call(ctx, http.MethodHead, "/api/v1/rules", nil, nil); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && resp.Header.Get("X-Rules-Hash") == hash {
			res.OK, res.Action = true, "in sync"
			return res
		}
	}

	hdr := http.Header{}
	hdr.Set("Content-Type", "application/yaml")
	hdr.Set("X-Rules-Origin", origin)
	resp, err := c.call(ctx, http.MethodPut, "/api/v1/rules", strings.NewReader(string(raw)), hdr)
	if err != nil {
		res.Action, res.Error = "failed", "agent unreachable: "+err.Error()
		return res
	}
	defer resp.Body.Close()
	var body struct {
		Hash      string `json:"hash"`
		Unchanged bool   `json:"unchanged"`
		Error     string `json:"error"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		res.Action, res.Error = "failed", body.Error
		if res.Error == "" {
			res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return res
	}
	res.OK, res.Action = true, "applied"
	if body.Unchanged {
		res.Action = "in sync"
	}
	s.log.Info("rules pushed", "agent", a.Name, "hash", body.Hash, "origin", origin)
	return res
}

// pushToNewMember applies the rules of the agent's (effective) group to it,
// e.g. right after it joined.
func (s *Server) pushToNewMember(ctx context.Context, a AgentRecord) *PushResult {
	name := EffectiveGroup(a, s.store.Groups())
	if name == "" || a.Revoked {
		return nil
	}
	g, ok := s.store.Group(name)
	if !ok || g.RulesHash == "" {
		return nil
	}
	raw, hash := s.targetFor(g, a, s.store.Members(g.Name))
	res := s.ensureRules(ctx, a, raw, hash, "group:"+g.Name)
	st := s.state(g.Name)
	s.stMu.Lock()
	st.Results[a.Name] = res
	s.stMu.Unlock()
	return &res
}

func gitSourceText(g *GitSource) string {
	if g == nil {
		return ""
	}
	if g.Provider == "url" {
		return maskURL(g.Path)
	}
	return fmt.Sprintf("%s %s@%s:%s", g.Provider, g.Repo, g.Ref, g.Path)
}
