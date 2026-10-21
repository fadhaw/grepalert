package dashboard

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fadhaw/grepalert/internal/rules"
)

// Config holds the dashboard's own settings. Agents and groups are managed in
// the UI and saved to DataFile.
type Config struct {
	Listen  string `yaml:"listen"`
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	Auth    Auth   `yaml:"auth"`
	// DataFile stores agents, groups and group rules (default dashboard-data.json).
	DataFile string `yaml:"data_file"`
	// ReconcileInterval is how often group members are checked and re-pushed
	// the group's rules if they drifted or came back online (default 30s).
	ReconcileInterval rules.Duration `yaml:"reconcile_interval"`
	// EnrollmentToken is an optional fixed token agents can enroll with, for
	// automated setups (Ansible, Terraform, images). Tokens can also be
	// created and revoked in the UI.
	EnrollmentToken string `yaml:"enrollment_token"`
	// AuditFile is the append-only audit log (JSON lines). Default: audit.log
	// next to DataFile.
	AuditFile string `yaml:"audit_file"`
}

// Auth configures sign-in. With nothing configured the dashboard is open to
// anyone (a warning is shown); set a password, local users or OIDC.
type Auth struct {
	// Username/Password define a built-in local admin, e.g. for break-glass
	// access when SSO is down. More local users can be added in the UI.
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// OIDC enables single sign-on (Okta, Entra ID, Google, Keycloak, ...).
	OIDC *OIDCConfig `yaml:"oidc"`
	// Admins always get the admin role: emails/usernames, or "group:<name>"
	// for an identity-provider group. Use it to bootstrap access.
	Admins []string `yaml:"admins"`
	// SessionTTL is how long a sign-in lasts (default 12h).
	SessionTTL rules.Duration `yaml:"session_ttl"`
	// CookieSecure forces the Secure flag on the session cookie. By default
	// it is set when the request arrived over HTTPS (directly or via a proxy
	// sending X-Forwarded-Proto).
	CookieSecure bool `yaml:"cookie_secure"`
}

// OIDCConfig is an OpenID Connect identity provider.
type OIDCConfig struct {
	// Name is shown on the sign-in button, e.g. "Okta" or "Microsoft".
	Name   string `yaml:"name"`
	Issuer string `yaml:"issuer"` // e.g. https://login.microsoftonline.com/<tenant>/v2.0
	// DiscoveryURL is where the dashboard itself reaches the provider, when
	// that differs from Issuer (the public URL browsers use), e.g. inside
	// Docker or Kubernetes: http://keycloak:8080/realms/acme. Tokens must still
	// be issued by Issuer.
	DiscoveryURL string `yaml:"discovery_url"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// RedirectURL is this dashboard's callback: https://<host>/auth/callback
	RedirectURL string   `yaml:"redirect_url"`
	Scopes      []string `yaml:"scopes"` // default: openid email profile
	// GroupsClaim is the ID-token claim listing the user's groups (default
	// "groups"); role bindings can grant roles to these groups.
	GroupsClaim string `yaml:"groups_claim"`
	// AllowedDomains, if set, only admits users whose email is in one of
	// these domains.
	AllowedDomains []string `yaml:"allowed_domains"`
}

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
	c.setDefaults()
	if err := c.validateAuth(); err != nil {
		return c, err
	}
	return c, nil
}

func (c *Config) setDefaults() {
	if c.Listen == "" {
		c.Listen = ":9400"
	}
	if c.DataFile == "" {
		c.DataFile = "dashboard-data.json"
	}
	if c.ReconcileInterval <= 0 {
		c.ReconcileInterval = rules.Duration(30 * time.Second)
	}
	if c.AuditFile == "" {
		c.AuditFile = filepath.Join(filepath.Dir(c.DataFile), "audit.log")
	}
	if c.Auth.SessionTTL <= 0 {
		c.Auth.SessionTTL = rules.Duration(12 * time.Hour)
	}
	if o := c.Auth.OIDC; o != nil {
		if len(o.Scopes) == 0 {
			o.Scopes = []string{"openid", "email", "profile"}
		}
		if o.GroupsClaim == "" {
			o.GroupsClaim = "groups"
		}
		if o.Name == "" {
			o.Name = "single sign-on"
		}
	}
}

func (c Config) validateAuth() error {
	if o := c.Auth.OIDC; o != nil {
		if o.Issuer == "" || o.ClientID == "" || o.RedirectURL == "" {
			return fmt.Errorf("auth.oidc: issuer, client_id and redirect_url are required")
		}
	}
	if (c.Auth.Username == "") != (c.Auth.Password == "") {
		return fmt.Errorf("auth: set both username and password, or neither")
	}
	return nil
}
