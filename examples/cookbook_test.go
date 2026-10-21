package examples_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/agent"
	"github.com/fadhaw/grepalert/internal/rules"
)

// TestCookbook runs every recipe in cookbook/ through the real engine: the
// "#   in:" lines of its header are fed to it in order, and the webhook
// bodies it sends must be the "#   out:" lines, in order. A recipe without
// "in:" lines only has to load.
func TestCookbook(t *testing.T) {
	files, err := filepath.Glob("cookbook/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no recipes in cookbook/: %v", err)
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			setEnv(t, raw)
			c, err := rules.Parse(raw)
			if err != nil {
				t.Fatalf("does not load: %v", err)
			}

			var in, want []string
			for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
				if v, ok := strings.CutPrefix(line, "#   in:  "); ok {
					in = append(in, v)
				} else if v, ok := strings.CutPrefix(line, "#   out: "); ok {
					want = append(want, v)
				}
			}
			if len(in) == 0 {
				if len(want) > 0 {
					t.Fatal("out: lines without in: lines")
				}
				return
			}

			var got []string
			for _, a := range agent.Simulate(c, in, time.Second).Alerts {
				for _, d := range a.Deliveries {
					if d.Error != "" {
						t.Errorf("%s alert of %s, webhook %s: %s", a.Kind, a.Rule, d.Webhook, d.Error)
					}
					got = append(got, d.Body)
				}
			}
			if len(got) != len(want) {
				t.Fatalf("%d webhook bodies, the recipe says %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
			}
			for i := range want {
				if !sameBody(got[i], want[i]) {
					t.Errorf("body %d:\n got: %s\nwant: %s", i+1, got[i], want[i])
				}
			}
		})
	}
}

// The cookbook page shows every recipe as it is.
func TestCookbookPageShowsTheRecipes(t *testing.T) {
	page, err := os.ReadFile("../docs/cookbook.md")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("cookbook/*.yaml")
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		recipe := strings.TrimRight(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
		if !strings.Contains(strings.ReplaceAll(string(page), "\r\n", "\n"), recipe) {
			t.Errorf("docs/cookbook.md does not show %s as it is", path)
		}
	}
}

// sameBody compares two bodies as JSON when both are JSON (so the recipe can
// write a multi-line template's output on one line), as text otherwise.
func sameBody(got, want string) bool {
	var g, w any
	if json.Unmarshal([]byte(got), &g) == nil && json.Unmarshal([]byte(want), &w) == nil {
		return reflect.DeepEqual(g, w)
	}
	return got == want
}
