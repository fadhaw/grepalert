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
	"runtime"
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

// When Run returns, the dashboard connection has stopped too: nothing is
// still writing files (identity, rules, silences) next to the rules file.
// Before, Run returned at once, and a test's temp dir sometimes could not be
// deleted because the agent was still saving a file into it.
func TestRunWaitsForDashboardConnection(t *testing.T) {
	dir := t.TempDir()
	late := filepath.Join(dir, "written-by-request")
	var sent sync.Once
	dash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/enroll":
			json.NewEncoder(w).Encode(map[string]string{"agent_id": "a1", "secret": "s", "name": "edge-01"})
		case "/agent/v1/poll":
			first := false
			sent.Do(func() { first = true })
			if first { // one request for the agent, then hold the poll like the dashboard does
				json.NewEncoder(w).Encode(map[string]any{"requests": []map[string]any{{
					"id": "r1", "method": "GET", "path": "/api/v1/status",
					"deadline": time.Now().Add(time.Minute)}}})
				return
			}
			// Read the body first, as the dashboard does: only then does the
			// server notice the agent hanging up and end the request.
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer dash.Close()

	a := New(Config{
		Name:      "edge-01",
		RulesFile: filepath.Join(dir, "rules.yaml"),
		StateFile: "off",
		Dashboard: DashboardConfig{URL: dash.URL, EnrollmentToken: "token"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// A request that is still being handled, and then writes a file, when the
	// agent is stopped.
	handling := make(chan struct{})
	a.conn.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(handling)
		time.Sleep(300 * time.Millisecond)
		os.WriteFile(late, []byte("done"), 0o644)
	})
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan error, 1)
	go func() { ran <- a.Run(ctx) }()

	select {
	case <-handling:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never got the request")
	}
	cancel()
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	if _, err := os.Stat(late); err != nil {
		t.Fatal("Run returned while the dashboard connection was still handling a request")
	}
}

// syncBuffer is a bytes.Buffer safe for a logger and a test to share.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// On start the agent logs which files it follows, which it waits for, and
// why a pattern matches nothing, so a wrong path or permission is visible.
func TestAgentLogsTheFilesItFollows(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	os.Mkdir(logs, 0o755)
	appendFile(t, filepath.Join(logs, "app.log"), "")
	files := []string{
		filepath.Join(logs, "*.log"),                    // matches app.log
		filepath.Join(logs, "later.log"),                // not created yet
		filepath.Join(dir, "no-such-dir", "*", "x.log"), // nothing there
	}
	locked := filepath.Join(dir, "locked")
	lockedCheck := runtime.GOOS != "windows" && os.Geteuid() != 0 // chmod doesn't stop Windows or root
	if lockedCheck {
		os.MkdirAll(filepath.Join(locked, "server1"), 0o755)
		os.Chmod(locked, 0o000)
		t.Cleanup(func() { os.Chmod(locked, 0o755) })
		files = append(files, filepath.Join(locked, "*", "*.log"))
	}
	quoted := make([]string, len(files))
	for i, f := range files {
		quoted[i] = fmt.Sprintf("%q", f)
	}
	rulesPath := filepath.Join(dir, "rules.yaml")
	os.WriteFile(rulesPath, []byte("webhooks:\n  - name: h\n    url: http://127.0.0.1:1/hook\nrules:\n"+
		"  - name: errors\n    files: ["+strings.Join(quoted, ", ")+"]\n    pattern: ERROR\n    webhooks: [h]\n"), 0o644)

	var out syncBuffer
	a := New(Config{RulesFile: rulesPath, StateFile: "off", RescanInterval: rules.Duration(50 * time.Millisecond)},
		slog.New(slog.NewTextHandler(&out, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(300 * time.Millisecond) // several rescans: each message must still appear once
	cancel()
	<-done
	log := out.String()

	// expect checks that exactly `times` log lines contain all of parts.
	expect := func(times int, parts ...string) {
		t.Helper()
		n := 0
		for _, line := range strings.Split(log, "\n") {
			all := line != ""
			for _, p := range parts {
				all = all && strings.Contains(line, p)
			}
			if all {
				n++
			}
		}
		if n != times {
			t.Errorf("%d log lines with %q, want %d\n%s", n, parts, times, log)
		}
	}
	expect(1, `msg="following file"`, filepath.Join(logs, "app.log"), "rules=errors", "from=end")
	expect(1, `msg="following file"`, filepath.Join(logs, "later.log"), `from="beginning, once created"`)
	expect(1, `msg="file does not exist yet, waiting for it"`, filepath.Join(logs, "later.log"))
	expect(1, `msg="no files match yet"`, files[2], `nothing named \"no-such-dir\"`)
	if lockedCheck {
		expect(1, "level=WARN", `msg="no files match"`, files[3], "cannot list "+locked+": permission denied")
		found := false
		for _, e := range a.Events(100) {
			found = found || (e.Type == "error" && strings.Contains(e.Message, "permission denied"))
		}
		if !found {
			t.Error("no error event for the directory the agent cannot list")
		}
	}
}
