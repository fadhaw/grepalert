package agent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fadhaw/grepalert/internal/rules"
)

// Config is the agent's own settings (agent.yaml). Rules live in a separate
// file (RulesFile) so they can be pushed by the dashboard or synced from git
// without touching agent settings.
type Config struct {
	Name      string `yaml:"name"`
	Listen    string `yaml:"listen"` // "off" disables the inbound API
	Token     string `yaml:"token"`
	TLSCert   string `yaml:"tls_cert"`
	TLSKey    string `yaml:"tls_key"`
	RulesFile string `yaml:"rules_file"`
	// LocalRulesFile holds extra rules for this machine only. They run on
	// top of the rules in RulesFile (which a dashboard group may manage) and
	// may only add rules, never replace the group's. Defaults to
	// rules.local.yaml next to RulesFile; "off" disables it.
	LocalRulesFile string `yaml:"local_rules_file"`

	// Dashboard makes the agent connect out to a dashboard (enroll + long-poll)
	// instead of, or as well as, serving its API on Listen. Labels describe
	// this agent; dashboard groups can auto-add agents by label.
	Dashboard    DashboardConfig   `yaml:"dashboard"`
	Labels       map[string]string `yaml:"labels"`
	IdentityFile string            `yaml:"identity_file"`

	// StateFile stores read positions so a restart resumes where the agent
	// stopped. Defaults to grepalert.state.json next to RulesFile; "off"
	// disables it.
	StateFile     string         `yaml:"state_file"`
	StateInterval rules.Duration `yaml:"state_interval"`

	// StartFrom is where to begin reading files that exist at startup:
	// "end" (default, only new lines) or "beginning".
	StartFrom    string         `yaml:"start_from"`
	PollInterval rules.Duration `yaml:"poll_interval"`
	// IdlePollInterval is how far polling backs off for files with no new
	// data (they return to PollInterval as soon as data arrives).
	IdlePollInterval rules.Duration `yaml:"idle_poll_interval"`
	// ReadWorkers is how many files are read in parallel; it also caps how
	// many CPU cores the agent uses while catching up on a backlog.
	ReadWorkers    int            `yaml:"read_workers"`
	RescanInterval rules.Duration `yaml:"rescan_interval"`
	MaxLineBytes   int            `yaml:"max_line_bytes"`

	QueueSize   int `yaml:"queue_size"`
	Workers     int `yaml:"workers"`
	Retries     int `yaml:"retries"`
	EventBuffer int `yaml:"event_buffer"`

	// Kubernetes is used by rules with a `kubernetes:` source: how to reach
	// the cluster (in-cluster service account by default).
	Kubernetes KubernetesConfig `yaml:"kubernetes"`

	// MemoryLimit is a soft Go runtime limit (e.g. "64MiB"). The GC works
	// harder as the heap nears it, keeping RSS flat.
	MemoryLimit ByteSize `yaml:"memory_limit"`
}

func (c *Config) setDefaults() {
	if c.Listen == "" && c.Dashboard.URL != "" {
		c.Listen = "off" // connected agents need no inbound port
	}
	if c.Listen == "" {
		c.Listen = ":9300"
	}
	if c.RulesFile == "" {
		c.RulesFile = "rules.yaml"
	}
	if c.LocalRulesFile == "" {
		c.LocalRulesFile = filepath.Join(filepath.Dir(c.RulesFile), "rules.local.yaml")
	}
	if c.IdentityFile == "" {
		c.IdentityFile = filepath.Join(filepath.Dir(c.RulesFile), "grepalert.identity.json")
	}
	if c.StateFile == "" {
		c.StateFile = filepath.Join(filepath.Dir(c.RulesFile), "grepalert.state.json")
	}
	if c.StateInterval <= 0 {
		c.StateInterval = rules.Duration(5 * time.Second)
	}
	if c.StartFrom == "" {
		c.StartFrom = "end"
	}
	if c.PollInterval <= 0 {
		c.PollInterval = rules.Duration(500 * time.Millisecond)
	}
	if c.IdlePollInterval <= 0 {
		c.IdlePollInterval = rules.Duration(2 * time.Second)
	}
	if c.IdlePollInterval < c.PollInterval {
		c.IdlePollInterval = c.PollInterval
	}
	if c.ReadWorkers <= 0 {
		c.ReadWorkers = 4
	}
	if c.RescanInterval <= 0 {
		c.RescanInterval = rules.Duration(10 * time.Second)
	}
	if c.MaxLineBytes <= 0 {
		c.MaxLineBytes = 16 * 1024
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 1000
	}
	if c.Workers <= 0 {
		c.Workers = 2
	}
	if c.Retries < 0 {
		c.Retries = 0
	} else if c.Retries == 0 {
		c.Retries = 2
	}
	if c.EventBuffer <= 0 {
		c.EventBuffer = 500
	}
	if c.Kubernetes.MaxStreams <= 0 {
		c.Kubernetes.MaxStreams = 200
	}
	if c.MemoryLimit == 0 {
		c.MemoryLimit = 64 << 20
	}
}

// LoadConfig reads agent.yaml. ${VAR} references are expanded from the environment.
func LoadConfig(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	raw = []byte(os.Expand(string(raw), os.Getenv))
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.StartFrom != "" && c.StartFrom != "end" && c.StartFrom != "beginning" {
		return c, fmt.Errorf("%s: start_from must be \"end\" or \"beginning\"", path)
	}
	c.setDefaults()
	return c, nil
}

// ByteSize parses sizes like "64MiB", "512KB", "1G" or plain bytes.
type ByteSize int64

func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*b = ByteSize(v)
	return nil
}

func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		m      int64
	}{{"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.m
			break
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return v * mult, nil
}
