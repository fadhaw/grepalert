package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

// TestRestartDoesNotMissLines runs the agent, stops it, writes lines while it
// is down and checks that the restarted agent alerts on exactly those lines.
func TestRestartDoesNotMissLines(t *testing.T) {
	var mu sync.Mutex
	var got []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a Alert
		json.NewDecoder(r.Body).Decode(&a)
		mu.Lock()
		got = append(got, a.Line)
		mu.Unlock()
	}))
	defer hook.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	rulesPath := filepath.Join(dir, "rules.yaml")
	rulesYAML := fmt.Sprintf("webhooks:\n  - name: h\n    url: %s\nrules:\n  - name: err\n    files: [%q]\n    pattern: ERROR\n    webhooks: [h]\n", hook.URL, logPath)
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	appendFile(t, logPath, "ERROR before first start (history, ignored)\n")

	cfg := Config{
		RulesFile:      rulesPath,
		PollInterval:   rules.Duration(20 * time.Millisecond),
		RescanInterval: rules.Duration(time.Hour),
		StateInterval:  rules.Duration(time.Hour), // only the shutdown save matters here
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	run := func(writes ...string) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error)
		a := New(cfg, log)
		go func() { done <- a.Run(ctx) }()
		time.Sleep(150 * time.Millisecond) // let tailers open the file
		for _, w := range writes {
			appendFile(t, logPath, w)
		}
		time.Sleep(150 * time.Millisecond)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}

	run("ERROR one\n")
	if _, err := os.Stat(filepath.Join(dir, "grepalert.state.json")); err != nil {
		t.Fatalf("state file not written: %v", err)
	}

	appendFile(t, logPath, "ERROR while stopped\nINFO fine\n")
	run("ERROR two\n")

	mu.Lock()
	defer mu.Unlock()
	// Each line alerts exactly once. Delivery order across lines is not
	// guaranteed (webhooks are sent by parallel workers), so compare sorted.
	want := []string{"ERROR one", "ERROR two", "ERROR while stopped"}
	sort.Strings(got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("alerts = %q, want %q", got, want)
	}
}

// TestGlobPicksUpNewFiles checks that a *.log rule tails existing files and
// files created later, and ignores files that do not match.
func TestGlobPicksUpNewFiles(t *testing.T) {
	var mu sync.Mutex
	var got []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a Alert
		json.NewDecoder(r.Body).Decode(&a)
		mu.Lock()
		got = append(got, filepath.Base(a.File)+": "+a.Line)
		mu.Unlock()
	}))
	defer hook.Close()

	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	os.Mkdir(logs, 0o755)
	appendFile(t, filepath.Join(logs, "a.log"), "")
	rulesPath := filepath.Join(dir, "rules.yaml")
	os.WriteFile(rulesPath, []byte(fmt.Sprintf("webhooks:\n  - name: h\n    url: %s\nrules:\n  - name: err\n    files: [%q]\n    pattern: ERROR\n    webhooks: [h]\n",
		hook.URL, filepath.Join(logs, "*.log"))), 0o644)

	a := New(Config{RulesFile: rulesPath, StateFile: "off",
		PollInterval: rules.Duration(20 * time.Millisecond), RescanInterval: rules.Duration(100 * time.Millisecond)},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(150 * time.Millisecond)

	appendFile(t, filepath.Join(logs, "a.log"), "ERROR in a\n")
	appendFile(t, filepath.Join(logs, "b.log"), "ERROR in b, created after start\n")
	appendFile(t, filepath.Join(logs, "c.txt"), "ERROR not a .log file\n")
	time.Sleep(400 * time.Millisecond)
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	want := map[string]bool{"a.log: ERROR in a": true, "b.log: ERROR in b, created after start": true}
	if len(got) != len(want) {
		t.Fatalf("alerts = %q", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected alert %q (all: %q)", g, got)
		}
	}
}

// A broken rules file is reported once, not on every check, and a fixed
// version is applied.
func TestBrokenRulesFileReportedOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	good := "webhooks: [{name: h, url: 'http://127.0.0.1:1/'}]\nrules:\n  - {name: a, files: [/x], pattern: A, webhooks: [h]}\n"
	os.WriteFile(path, []byte(good), 0o644)
	a := New(Config{RulesFile: path, StateFile: "off"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := a.loadRulesFile(true); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("rules: [{name: b, pattern: '('}]\n"), 0o644)
	if err := a.loadRulesFile(false); err == nil {
		t.Fatal("broken file accepted")
	}
	if err := a.loadRulesFile(false); err != nil {
		t.Fatalf("the same broken file was reported again: %v", err)
	}
	os.WriteFile(path, []byte(strings.Replace(good, "pattern: A", "pattern: B", 1)), 0o644)
	if err := a.loadRulesFile(false); err != nil || a.Rules().Rules[0].Pattern != "B" {
		t.Fatalf("fixed file: err %v, pattern %q", err, a.Rules().Rules[0].Pattern)
	}
}
