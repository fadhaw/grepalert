package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

// AgentRecord is an agent the dashboard manages. It is either:
//   - direct: the dashboard calls the agent's API at URL (added in the UI), or
//   - connected: the agent enrolled itself and keeps an outbound connection to
//     the dashboard, so it needs no inbound port.
type AgentRecord struct {
	Name string `json:"name"`
	Mode string `json:"mode,omitempty"` // "" (direct) or "connected"
	// Group is set by an admin. When empty, a connected agent joins the first
	// group (by name) whose label selector matches its labels.
	Group   string    `json:"group,omitempty"`
	AddedAt time.Time `json:"added_at"`

	// Direct agents.
	URL                string `json:"url,omitempty"`
	Token              string `json:"token,omitempty"` // may be ${ENV}
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`

	// Connected agents.
	ID          string            `json:"id,omitempty"`
	SecretHash  string            `json:"secret_hash,omitempty"` // sha256 of the agent's secret
	Labels      map[string]string `json:"labels,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`
	Version     string            `json:"version,omitempty"`
	EnrolledVia string            `json:"enrolled_via,omitempty"` // enrollment token name
	Revoked     bool              `json:"revoked,omitempty"`
}

func (a AgentRecord) Connected() bool { return a.Mode == "connected" }

// GitSource is where a git-backed group reads its rules from.
type GitSource struct {
	Provider string `json:"provider"` // github, gitlab or url
	// BaseURL overrides the API endpoint for GitHub Enterprise
	// (https://ghe.example.com/api/v3) or self-hosted GitLab.
	BaseURL string `json:"base_url,omitempty"`
	Repo    string `json:"repo,omitempty"` // owner/name or group/project
	Ref     string `json:"ref,omitempty"`  // branch, tag or commit
	Path    string `json:"path"`           // file in the repo; for "url" the full URL
	Token   string `json:"token,omitempty"`
	// Interval is how often to re-fetch, e.g. "5m". Empty means manual only.
	Interval string `json:"interval,omitempty"`
}

// GroupRecord is a set of agents sharing one rule set.
type GroupRecord struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Source      string     `json:"source"` // "manual" or "git"
	Git         *GitSource `json:"git,omitempty"`
	// Selector auto-adds connected agents whose labels contain all of these
	// key/value pairs (unless an admin assigned the agent elsewhere).
	Selector map[string]string `json:"selector,omitempty"`
	// Fleet controls deduplication of alerts across the group's agents.
	Fleet FleetSettings `json:"fleet"`
	// OpsWebhookURL receives agent-down/up alerts for this group; empty
	// uses the dashboard-wide ops webhook (Settings).
	OpsWebhookURL string `json:"ops_webhook_url,omitempty"`
	// Rules is the group's rule set: edited in the dashboard (manual) or the
	// last version fetched from git.
	Rules          string    `json:"rules,omitempty"`
	RulesHash      string    `json:"rules_hash,omitempty"`
	RulesUpdatedAt time.Time `json:"rules_updated_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`

	// Rollout makes rule changes reach the group's agents in stages.
	Rollout RolloutSettings `json:"rollout"`
	// RolloutState is the latest staged rollout, if any.
	RolloutState *Rollout `json:"rollout_state,omitempty"`
	// GitPaused stops a git group from following git, e.g. after a rollback
	// (otherwise the next fetch would bring the bad version back). It holds
	// the reason; a manual sync clears it.
	GitPaused string `json:"git_paused,omitempty"`
}

type storeData struct {
	Version  int               `json:"version"`
	Agents   []AgentRecord     `json:"agents"`
	Groups   []GroupRecord     `json:"groups"`
	Tokens   []EnrollmentToken `json:"enrollment_tokens,omitempty"`
	Silences []Silence         `json:"silences,omitempty"`
	Settings Settings          `json:"settings"`
	// Versions holds each group's rule history, newest last.
	Versions map[string][]RuleVersion `json:"rule_versions,omitempty"`

	// Access control.
	Users      []LocalUser          `json:"users,omitempty"`
	Bindings   []RoleBinding        `json:"role_bindings,omitempty"`
	SessionKey []byte               `json:"session_key,omitempty"`
	ValidAfter map[string]time.Time `json:"sessions_valid_after,omitempty"`
}

// Store persists agents and groups to a JSON file. It holds tokens, so the
// file is written with 0600 permissions.
type Store struct {
	path string
	mu   sync.Mutex
	data storeData
}

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func checkName(kind, name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("%s name must be 1-64 characters: letters, digits, '.', '_' or '-'", kind)
	}
	return nil
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, data: storeData{Version: 1}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// Groups from before versioning: their current rules are version one.
	for _, g := range s.data.Groups {
		if g.RulesHash != "" && len(s.data.Versions[g.Name]) == 0 {
			s.addVersionLocked(g.Name, RuleVersion{Hash: g.RulesHash, Rules: g.Rules, Time: g.RulesUpdatedAt, Source: "existing"})
		}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	// CreateTemp creates the file with 0600, which the rename keeps.
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".dashboard-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func (s *Store) Agents() []AgentRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]AgentRecord(nil), s.data.Agents...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) Agent(name string) (AgentRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.data.Agents {
		if a.Name == name {
			return a, true
		}
	}
	return AgentRecord{}, false
}

// AddAgent stores a new agent.
func (s *Store) AddAgent(a AgentRecord) error {
	if err := checkName("agent", a.Name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.data.Agents {
		if x.Name == a.Name {
			return fmt.Errorf("an agent named %q already exists", a.Name)
		}
	}
	if a.Group != "" && !s.hasGroupLocked(a.Group) {
		return fmt.Errorf("group %q does not exist", a.Group)
	}
	a.AddedAt = time.Now()
	s.data.Agents = append(s.data.Agents, a)
	return s.saveLocked()
}

// UpdateAgent applies fn to the named agent and saves. fn must not rename it.
func (s *Store) UpdateAgent(name string, fn func(*AgentRecord) error) (AgentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Agents {
		if s.data.Agents[i].Name != name {
			continue
		}
		a := s.data.Agents[i]
		if err := fn(&a); err != nil {
			return AgentRecord{}, err
		}
		if a.Group != "" && !s.hasGroupLocked(a.Group) {
			return AgentRecord{}, fmt.Errorf("group %q does not exist", a.Group)
		}
		a.Name = name
		s.data.Agents[i] = a
		return a, s.saveLocked()
	}
	return AgentRecord{}, fmt.Errorf("agent %q not found", name)
}

func (s *Store) DeleteAgent(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.data.Agents {
		if x.Name == name {
			s.data.Agents = append(s.data.Agents[:i], s.data.Agents[i+1:]...)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("agent %q not found", name)
}

func (s *Store) Groups() []GroupRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]GroupRecord(nil), s.data.Groups...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) Group(name string) (GroupRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.data.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return GroupRecord{}, false
}

func (s *Store) hasGroupLocked(name string) bool {
	for _, g := range s.data.Groups {
		if g.Name == name {
			return true
		}
	}
	return false
}

// Members returns the (non-revoked) agents in a group, whether assigned by an
// admin or matched by the group's label selector.
func (s *Store) Members(group string) []AgentRecord {
	groups := s.Groups()
	var out []AgentRecord
	for _, a := range s.Agents() {
		if !a.Revoked && EffectiveGroup(a, groups) == group {
			out = append(out, a)
		}
	}
	return out
}

// EffectiveGroup is the group an agent belongs to: the one an admin assigned,
// otherwise the first group (sorted by name) whose selector matches its
// labels, otherwise none. groups must be sorted by name.
func EffectiveGroup(a AgentRecord, groups []GroupRecord) string {
	if a.Group != "" {
		return a.Group
	}
	for _, g := range groups {
		if SelectorMatches(g.Selector, a.Labels) {
			return g.Name
		}
	}
	return ""
}

// SelectorMatches reports whether labels contain every pair in sel. An empty
// selector matches nothing, so groups without one never auto-add agents.
func SelectorMatches(sel, labels map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

var validLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,62}$`)

// CheckLabels validates label keys and values.
func CheckLabels(labels map[string]string) error {
	if len(labels) > 32 {
		return errors.New("at most 32 labels are allowed")
	}
	for k, v := range labels {
		if !validLabel.MatchString(k) || !validLabel.MatchString(v) {
			return fmt.Errorf("invalid label %q=%q: use 1-63 letters, digits, '.', '_', '/' or '-'", k, v)
		}
	}
	return nil
}

func validateGroup(g *GroupRecord) error {
	if err := checkName("group", g.Name); err != nil {
		return err
	}
	if err := g.Fleet.validate(); err != nil {
		return err
	}
	if g.OpsWebhookURL != "" && !strings.HasPrefix(g.OpsWebhookURL, "http://") && !strings.HasPrefix(g.OpsWebhookURL, "https://") && !strings.HasPrefix(g.OpsWebhookURL, "${") {
		return errors.New("the agent-down webhook must be an http(s) URL")
	}
	if err := CheckLabels(g.Selector); err != nil {
		return fmt.Errorf("selector: %w", err)
	}
	if err := g.Rollout.validate(); err != nil {
		return fmt.Errorf("staged rollout: %w", err)
	}
	switch g.Source {
	case "manual":
		g.Git = nil
	case "git":
		if g.Git == nil {
			return errors.New("git settings are required for a git group")
		}
		gs := g.Git
		switch gs.Provider {
		case "github", "gitlab":
			if gs.Repo == "" || gs.Path == "" {
				return errors.New("repository and file path are required")
			}
		case "url":
			if gs.Path == "" {
				return errors.New("the URL of the rules file is required")
			}
		default:
			return errors.New("provider must be github, gitlab or url")
		}
		if gs.Ref == "" && gs.Provider != "url" {
			gs.Ref = "main"
		}
		if gs.Interval != "" {
			d, err := time.ParseDuration(gs.Interval)
			if err != nil || d < 10*time.Second {
				return errors.New("sync interval must be a duration of at least 10s, e.g. 5m")
			}
		}
	default:
		return errors.New(`source must be "manual" or "git"`)
	}
	return nil
}

// AddGroup stores a new group; author is recorded on its first rule version.
func (s *Store) AddGroup(g GroupRecord, author string) error {
	if err := validateGroup(&g); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasGroupLocked(g.Name) {
		return fmt.Errorf("a group named %q already exists", g.Name)
	}
	g.CreatedAt = time.Now()
	g.RolloutState, g.GitPaused = nil, ""
	if g.Rules != "" {
		g.RulesHash = rules.Hash([]byte(g.Rules))
		g.RulesUpdatedAt = time.Now()
		s.addVersionLocked(g.Name, RuleVersion{Hash: g.RulesHash, Rules: g.Rules, Time: g.RulesUpdatedAt, Author: author, Source: "created"})
	}
	s.data.Groups = append(s.data.Groups, g)
	return s.saveLocked()
}

// UpdateGroup changes a group's description and source. Rules are kept; an
// empty git token keeps the previous one.
func (s *Store) UpdateGroup(g GroupRecord) error {
	if err := validateGroup(&g); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.data.Groups {
		if x.Name != g.Name {
			continue
		}
		if g.Git != nil && g.Git.Token == "" && x.Git != nil {
			g.Git.Token = x.Git.Token
		}
		g.Rules, g.RulesHash, g.RulesUpdatedAt, g.CreatedAt = x.Rules, x.RulesHash, x.RulesUpdatedAt, x.CreatedAt
		g.RolloutState, g.GitPaused = x.RolloutState, x.GitPaused
		s.data.Groups[i] = g
		return s.saveLocked()
	}
	return fmt.Errorf("group %q not found", g.Name)
}

// SetGroupRules stores a new rule set for a group and records it as a
// version. fn, if set, adjusts the group in the same save (e.g. its rollout).
func (s *Store) SetGroupRules(name string, raw []byte, v RuleVersion, fn func(*GroupRecord)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.data.Groups {
		if g.Name == name {
			g.Rules, g.RulesHash, g.RulesUpdatedAt = string(raw), rules.Hash(raw), time.Now()
			if fn != nil {
				fn(&g)
			}
			s.data.Groups[i] = g
			v.Hash, v.Rules, v.Time = g.RulesHash, g.Rules, g.RulesUpdatedAt
			s.addVersionLocked(name, v)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("group %q not found", name)
}

// MutateGroup applies fn to a group's runtime fields (rollout, git pause)
// and saves. fn must not change its settings or rules.
func (s *Store) MutateGroup(name string, fn func(*GroupRecord) error) (GroupRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Groups {
		if s.data.Groups[i].Name != name {
			continue
		}
		g := s.data.Groups[i]
		if err := fn(&g); err != nil {
			return GroupRecord{}, err
		}
		s.data.Groups[i] = g
		return g, s.saveLocked()
	}
	return GroupRecord{}, fmt.Errorf("group %q not found", name)
}

// DeleteGroup removes a group. Its agents become ungrouped and keep running
// the rules they have.
func (s *Store) DeleteGroup(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.data.Groups {
		if g.Name == name {
			s.data.Groups = append(s.data.Groups[:i], s.data.Groups[i+1:]...)
			delete(s.data.Versions, name)
			for j := range s.data.Agents {
				if s.data.Agents[j].Group == name {
					s.data.Agents[j].Group = ""
				}
			}
			return s.saveLocked()
		}
	}
	return fmt.Errorf("group %q not found", name)
}
