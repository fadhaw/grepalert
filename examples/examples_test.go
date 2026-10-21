// Package examples_test checks that every example configuration in this
// directory (and the configs embedded in the Kubernetes manifests) loads
// with the real parsers, so the examples in the docs never go stale.
package examples_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/fadhaw/grepalert/internal/agent"
	"github.com/fadhaw/grepalert/internal/dashboard"
	"github.com/fadhaw/grepalert/internal/rules"
)

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// setEnv gives every ${VAR} in raw a value: a URL for *URL variables
// (webhooks check theirs), a plain token otherwise.
func setEnv(t *testing.T, raw []byte) {
	for _, m := range envRef.FindAllSubmatch(raw, -1) {
		name := string(m[1])
		val := "example-" + strings.ToLower(name)
		if strings.HasSuffix(name, "_URL") {
			val = "https://hooks.example.test/" + strings.ToLower(name)
		}
		t.Setenv(name, val)
	}
}

// kind tells what a YAML file is from its name.
func kind(name string) string {
	base := filepath.Base(name)
	switch {
	case strings.Contains(base, ".local."):
		return "local-rules"
	case strings.Contains(base, "rules"):
		return "rules"
	case strings.Contains(base, "dashboard"):
		return "dashboard"
	case strings.Contains(base, "agent"):
		return "agent"
	}
	return ""
}

func check(t *testing.T, name string, raw []byte) {
	t.Helper()
	setEnv(t, raw)
	switch kind(name) {
	case "rules":
		if _, err := rules.Parse(raw); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	case "local-rules":
		// Local rules use the webhooks of the group rules next to them.
		base, err := os.ReadFile("compose/git-repo/rules.yaml")
		if err != nil {
			t.Fatal(err)
		}
		setEnv(t, base)
		if _, err := rules.ParseOverlay(base, raw); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	case "agent", "dashboard":
		tmp := filepath.Join(t.TempDir(), filepath.Base(name))
		if err := os.WriteFile(tmp, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		if kind(name) == "agent" {
			_, err = agent.LoadConfig(tmp)
		} else {
			_, err = dashboard.LoadConfig(tmp)
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExampleConfigs(t *testing.T) {
	checked := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte("\nkind: ")) || bytes.HasPrefix(raw, []byte("kind: ")) || bytes.Contains(raw, []byte("\napiVersion: ")) {
			checked += checkManifests(t, path, raw)
			return nil
		}
		if kind(path) == "" || strings.HasPrefix(filepath.ToSlash(path), "sso/") && strings.Contains(path, "realm") {
			return nil // compose files, realms and other non-grepalert YAML
		}
		if filepath.Base(path) == "compose.yaml" {
			return nil
		}
		check(t, path, raw)
		checked++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 15 {
		t.Fatalf("only %d example configs checked; did the layout change?", checked)
	}
	t.Logf("%d example configs load", checked)
}

// checkManifests validates the grepalert configs inside Kubernetes
// ConfigMaps (data keys agent.yaml, rules.yaml, ...).
func checkManifests(t *testing.T, path string, raw []byte) int {
	n := 0
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc struct {
			Kind string            `yaml:"kind"`
			Data map[string]string `yaml:"data"`
		}
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			return n
		} else if err != nil {
			t.Errorf("%s: %v", path, err)
			return n
		}
		if doc.Kind != "ConfigMap" {
			continue
		}
		for key, val := range doc.Data {
			check(t, path+"#"+key, []byte(val))
			n++
		}
	}
}

// The docs show these files; they must stay identical to what is tested.
func TestDocsShowTheExamples(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	// Each reference page embeds its complete example.
	for doc, ex := range map[string]string{
		"../docs/config-agent.md":     "agent.yaml",
		"../docs/config-rules.md":     "rules.yaml",
		"../docs/config-dashboard.md": "dashboard.yaml",
	} {
		if !strings.Contains(read(doc), strings.TrimRight(read(ex), "\n")) {
			t.Errorf("%s does not show the current examples/%s; paste it in again", doc, ex)
		}
	}
	// The README's quick start shows the quickstart files (without their
	// header comments).
	readme := read("../README.md")
	for _, f := range []string{"agent.yaml", "rules.yaml", "dashboard.yaml", "agent-connected.yaml"} {
		var body []string
		for _, l := range strings.Split(strings.TrimRight(read("quickstart/"+f), "\n"), "\n") {
			if len(body) == 0 && strings.HasPrefix(l, "#") {
				continue
			}
			body = append(body, l)
		}
		if !strings.Contains(readme, strings.Join(body, "\n")) {
			t.Errorf("README.md does not show examples/quickstart/%s as it is", f)
		}
	}
}

var (
	mdLink    = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	mdHeading = regexp.MustCompile(`(?m)^#{1,6} (.+)$`)
	notSlug   = regexp.MustCompile(`[^\p{L}\p{N} _-]`)
)

// anchors returns the GitHub anchors of a Markdown file's headings.
func anchors(md string) map[string]bool {
	out := map[string]bool{}
	inCode := false
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
		}
		if inCode {
			continue
		}
		if m := mdHeading.FindStringSubmatch(line); m != nil {
			slug := strings.ToLower(strings.TrimSpace(m[1]))
			slug = strings.ReplaceAll(notSlug.ReplaceAllString(slug, ""), " ", "-")
			out[slug] = true
		}
	}
	return out
}

// Every relative link in the README and docs points to a file that exists,
// and every #anchor to a heading in it.
func TestDocLinks(t *testing.T) {
	files, _ := filepath.Glob("../docs/*.md")
	files = append(files, "../README.md")
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range mdLink.FindAllStringSubmatch(string(raw), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			path, anchor, _ := strings.Cut(target, "#")
			resolved := f
			if path != "" {
				resolved = filepath.Join(filepath.Dir(f), path)
			}
			info, err := os.Stat(resolved)
			if err != nil {
				t.Errorf("%s: link to %s: no such file", f, target)
				continue
			}
			if anchor == "" || info.IsDir() || filepath.Ext(resolved) != ".md" {
				continue
			}
			doc, _ := os.ReadFile(resolved)
			if !anchors(string(doc))[anchor] {
				t.Errorf("%s: link to %s: no heading for #%s", f, target, anchor)
			}
		}
	}
}
