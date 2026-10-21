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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

// fakeKube is a tiny Kubernetes API: a pod list and follow-able logs.
type fakeKube struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	pods     []string            // running pods of app=checkout in namespace shop
	logs     map[string][]string // pod -> lines written so far ("<ts> <text>")
	notify   map[string]chan struct{}
	requests []string // log requests, with their query
	drop     map[string]chan struct{}
}

func newFakeKube(t *testing.T) *fakeKube {
	k := &fakeKube{t: t, logs: map[string][]string{}, notify: map[string]chan struct{}{}, drop: map[string]chan struct{}{}}
	k.srv = httptest.NewServer(http.HandlerFunc(k.serve))
	t.Cleanup(k.srv.Close)
	return k
}

func (k *fakeKube) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test-token" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "no token"})
		return
	}
	switch {
	case r.URL.Path == "/api/v1/namespaces/shop/pods":
		if r.URL.Query().Get("labelSelector") != "app=checkout" {
			k.t.Errorf("selector = %q", r.URL.Query().Get("labelSelector"))
		}
		k.mu.Lock()
		var items []map[string]any
		for _, p := range k.pods {
			items = append(items, map[string]any{
				"metadata": map[string]any{"name": p, "namespace": "shop"},
				"status": map[string]any{"containerStatuses": []any{
					map[string]any{"name": "api", "state": map[string]any{"running": map[string]any{}}},
					map[string]any{"name": "sidecar", "state": map[string]any{"waiting": map[string]any{}}},
				}},
			})
		}
		k.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"items": items})
	case strings.HasSuffix(r.URL.Path, "/log"):
		pod := strings.Split(r.URL.Path, "/")[6]
		q := r.URL.Query()
		k.mu.Lock()
		k.requests = append(k.requests, pod+"?"+q.Encode())
		if k.notify[pod] == nil {
			k.notify[pod] = make(chan struct{}, 100)
		}
		if k.drop[pod] == nil {
			k.drop[pod] = make(chan struct{})
		}
		notify, drop := k.notify[pod], k.drop[pod]
		// Like the API: tailLines=0 starts at the end, sinceTime from that second.
		sent := 0
		switch {
		case q.Get("tailLines") == "0":
			sent = len(k.logs[pod])
		case q.Get("sinceTime") != "":
			since, _ := time.Parse(time.RFC3339, q.Get("sinceTime"))
			for sent < len(k.logs[pod]) {
				ts, _ := time.Parse(time.RFC3339Nano, strings.SplitN(k.logs[pod][sent], " ", 2)[0])
				if !ts.Before(since) {
					break
				}
				sent++
			}
		}
		k.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			k.mu.Lock()
			lines := k.logs[pod][sent:]
			sent = len(k.logs[pod])
			k.mu.Unlock()
			for _, l := range lines {
				fmt.Fprintln(w, l)
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-drop:
				return
			case <-notify:
			case <-time.After(50 * time.Millisecond):
			}
		}
	default:
		http.NotFound(w, r)
	}
}

func (k *fakeKube) write(pod, text string) {
	k.mu.Lock()
	k.logs[pod] = append(k.logs[pod], time.Now().UTC().Format(time.RFC3339Nano)+" "+text)
	ch := k.notify[pod]
	k.mu.Unlock()
	if ch != nil {
		ch <- struct{}{}
	}
	time.Sleep(2 * time.Millisecond) // distinct timestamps
}

func (k *fakeKube) setPods(p ...string) {
	k.mu.Lock()
	k.pods = p
	k.mu.Unlock()
}

// dropStream ends a pod's current log stream, like an API server timeout.
func (k *fakeKube) dropStream(pod string) {
	k.mu.Lock()
	close(k.drop[pod])
	k.drop[pod] = make(chan struct{})
	k.mu.Unlock()
}

func (k *fakeKube) logRequests() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.requests...)
}

func (k *fakeKube) kubeconfig(t *testing.T, dir string) string {
	path := filepath.Join(dir, "kubeconfig")
	os.WriteFile(path, []byte(fmt.Sprintf(`apiVersion: v1
current-context: test
clusters: [{name: c, cluster: {server: %q}}]
users: [{name: u, user: {token: test-token}}]
contexts: [{name: test, context: {cluster: c, user: u}}]
`, k.srv.URL)), 0o600)
	return path
}

func TestKubernetesSource(t *testing.T) {
	kube := newFakeKube(t)
	var mu sync.Mutex
	var got []Alert
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a Alert
		json.NewDecoder(r.Body).Decode(&a)
		mu.Lock()
		got = append(got, a)
		mu.Unlock()
	}))
	defer hook.Close()
	alerts := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, a := range got {
			out = append(out, a.File+" "+a.Line)
		}
		return out
	}
	waitAlerts := func(n int) []string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if a := alerts(); len(a) >= n {
				return a
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %d alerts, have %v", n, alerts())
		return nil
	}

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	os.WriteFile(rulesPath, []byte(fmt.Sprintf(`webhooks: [{name: h, url: %q}]
rules:
  - name: errors
    kubernetes: {namespace: shop, selector: app=checkout, container: api}
    pattern: 'ERROR (?P<what>\w+)'
    webhooks: [h]
`, hook.URL)), 0o644)
	cfg := Config{RulesFile: rulesPath, StateFile: filepath.Join(dir, "state.json"),
		RescanInterval: rules.Duration(100 * time.Millisecond), StateInterval: rules.Duration(time.Hour),
		Kubernetes: KubernetesConfig{Kubeconfig: kube.kubeconfig(t, dir)}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	kube.setPods("checkout-1")
	kube.write("checkout-1", "ERROR history") // before the agent: not alerted
	ctx, cancel := context.WithCancel(context.Background())
	a := New(cfg, log)
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	time.Sleep(400 * time.Millisecond)

	kube.write("checkout-1", "INFO fine")
	kube.write("checkout-1", "ERROR one")
	if a := waitAlerts(1); a[0] != "k8s:shop/checkout-1/api ERROR one" {
		t.Fatalf("alerts = %v", a)
	}

	// A pod that appears later is read from its first line.
	kube.write("checkout-2", "ERROR early")
	kube.setPods("checkout-1", "checkout-2")
	waitAlerts(2)

	// A dropped stream resumes after the last line: nothing is repeated.
	kube.dropStream("checkout-1")
	time.Sleep(100 * time.Millisecond)
	kube.write("checkout-1", "ERROR after-reconnect")
	a3 := waitAlerts(3)
	time.Sleep(300 * time.Millisecond)
	if n := len(alerts()); n != 3 {
		t.Fatalf("after reconnect: %d alerts %v (a line was repeated)", n, alerts())
	}
	if !strings.Contains(strings.Join(a3, "|"), "checkout-2/api ERROR early") {
		t.Fatalf("alerts = %v", a3)
	}

	st := a.Status()
	if st.Kubernetes == nil || len(st.Kubernetes.Sources) != 1 || st.Kubernetes.Sources[0].Pods != 2 {
		t.Fatalf("kubernetes status = %+v", st.Kubernetes)
	}
	streams := 0
	for _, f := range st.Files {
		if strings.HasPrefix(f.Path, "k8s:") {
			streams++
		}
	}
	if streams != 2 {
		t.Fatalf("status files = %+v (want 2 streams; the waiting sidecar is skipped)", st.Files)
	}

	// A pod that is gone stops being followed.
	kube.setPods("checkout-1")
	waitFor(t, func() bool {
		for _, f := range a.Status().Files {
			if strings.Contains(f.Path, "checkout-2") {
				return false
			}
		}
		return true
	})

	// Restart: the saved position resumes the stream from its last line.
	cancel()
	<-done
	kube.write("checkout-1", "ERROR while-down")
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	b := New(cfg, log)
	done2 := make(chan struct{})
	go func() { b.Run(ctx2); close(done2) }()
	a4 := waitAlerts(4)
	if a4[3] != "k8s:shop/checkout-1/api ERROR while-down" {
		t.Fatalf("after restart = %v", a4)
	}
	reqs := kube.logRequests()
	if !strings.Contains(reqs[0], "tailLines=0") || strings.Contains(strings.Join(reqs, "|"), "checkout-2?container=api&follow=true&tailLines") {
		t.Errorf("log requests = %v", reqs)
	}
	if last := reqs[len(reqs)-1]; !strings.Contains(last, "sinceTime=") {
		t.Errorf("restart request = %s, want sinceTime", last)
	}
	cancel2()
	<-done2
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestKubeconfigErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kc")
	os.WriteFile(path, []byte(`current-context: eks
clusters: [{name: c, cluster: {server: "https://x"}}]
users: [{name: u, user: {exec: {command: aws}}}]
contexts: [{name: eks, context: {cluster: c, user: u}}]
`), 0o600)
	if _, err := kubeFromConfig(path, ""); err == nil || !strings.Contains(err.Error(), "kubectl proxy") {
		t.Errorf("exec plugin: err = %v", err)
	}
	if _, err := kubeFromConfig(path, "missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing context: err = %v", err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := newKubeClient(KubernetesConfig{}); err == nil || !strings.Contains(err.Error(), "kubeconfig") {
		t.Errorf("outside a cluster: err = %v", err)
	}
}
