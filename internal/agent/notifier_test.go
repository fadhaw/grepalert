package agent

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/alert"
)

// Every webhook delivery is logged: failures always, with the error and the
// attempts made; successes at debug, with the HTTP status.
func TestNotifierLogsDeliveries(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ok.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream down", http.StatusBadGateway)
	}))
	defer broken.Close()

	run := func(level slog.Level) string {
		var out syncBuffer
		n := newNotifier(10, 1, newRing(10), slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: level})))
		ctx, cancel := context.WithCancel(context.Background())
		n.start(ctx, 2)
		n.direct(Alert{Rule: "deploy-failed", Text: "x"}, []*alert.Hook{
			{Name: "chat", URL: ok.URL, Method: http.MethodPost, Timeout: 5 * time.Second},
			{Name: "pager", URL: broken.URL, Method: http.MethodPost, Timeout: 5 * time.Second},
		})
		deadline := time.Now().Add(10 * time.Second)
		for n.sender.Sent.Load()+n.sender.Failed.Load() < 2 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		n.wait()
		return out.String()
	}

	log := run(slog.LevelDebug)
	for _, want := range [][]string{
		{"level=DEBUG", `msg="webhook delivered"`, "rule=deploy-failed", "webhook=chat", "status=200", "attempts=1"},
		{"level=WARN", `msg="webhook delivery failed"`, "rule=deploy-failed", "webhook=pager", "attempts=2", `err="HTTP 502: upstream down"`},
	} {
		found := false
		for _, line := range strings.Split(log, "\n") {
			all := true
			for _, p := range want {
				all = all && strings.Contains(line, p)
			}
			found = found || all
		}
		if !found {
			t.Errorf("no log line with %q in:\n%s", want, log)
		}
	}

	// At the default level the failure is still logged, the success is not.
	log = run(slog.LevelInfo)
	if !strings.Contains(log, `msg="webhook delivery failed"`) || strings.Contains(log, "webhook delivered") {
		t.Errorf("at info level, want only the failure:\n%s", log)
	}
}

// A full queue is logged once per 10 seconds, not once per dropped alert.
func TestNotifierLogsFullQueueOnce(t *testing.T) {
	var out syncBuffer
	n := newNotifier(1, 0, newRing(10), slog.New(slog.NewTextHandler(&out, nil)))
	hook := []*alert.Hook{{Name: "chat", URL: "http://127.0.0.1:1", Method: http.MethodPost, Timeout: time.Second}}
	for i := 0; i < 5; i++ { // not started: the first fills the queue, the rest are dropped
		n.direct(Alert{Rule: "noisy"}, hook)
	}
	if c := strings.Count(out.String(), `msg="webhook queue full: alerts are being dropped"`); c != 1 {
		t.Fatalf("queue-full warnings = %d, want 1:\n%s", c, out.String())
	}
	if !strings.Contains(out.String(), "dropped_total=1") {
		t.Errorf("want the drop count in the warning:\n%s", out.String())
	}
}
