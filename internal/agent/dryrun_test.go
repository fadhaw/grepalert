package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fadhaw/grepalert/internal/rules"
)

func testAgent(t *testing.T, rulesYAML string) (*Agent, string) {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	cfg := Config{RulesFile: rulesPath, StateFile: "off"}
	a := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if rulesYAML != "" {
		if _, err := a.apply([]byte(rulesYAML), "test", true); err != nil {
			t.Fatal(err)
		}
	}
	return a, dir
}

func TestDryRunWindowAndSuppression(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	// 120 lines: the first 60 written 60-30 minutes ago, the rest in the last 30.
	var b strings.Builder
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&b, "2026-01-01 ERROR code=%d something broke\n", i%3)
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	size := int64(b.Len())
	lineLen := size / 120

	rule := func(name, suppress string) string {
		return fmt.Sprintf("webhooks:\n  - name: h\n    url: http://127.0.0.1:1/x\nrules:\n  - name: %s\n    files: [%q]\n    pattern: 'ERROR code=(?P<code>\\d)'\n    webhooks: [h]\n%s", name, logPath, suppress)
	}
	a, _ := testAgent(t, rule("errors", "    suppress: {window: 10m, group_by: code, summary: false}\n"))
	now := time.Now()
	a.hist[logPath] = &offsetHist{}
	a.hist[logPath].add(offsetSample{now.Add(-61 * time.Minute).UnixNano(), 0})
	a.hist[logPath].add(offsetSample{now.Add(-30 * time.Minute).UnixNano(), 60 * lineLen})
	a.hist[logPath].add(offsetSample{now.Add(-time.Second).UnixNano(), size})

	cand, err := rules.ParseWith([]byte(rule("errors-noisy", "")), rules.Options{AllowUnresolvedEnv: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.DryRun(context.Background(), cand, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Lines 0-1 fall in the minute before the window.
	if got := res.Candidate.Alerts; got < 116 || got > 120 {
		t.Errorf("candidate alerts = %d, want ~118", got)
	}
	// 3 codes, one alert per 10 minutes each, over an hour: ~18.
	if got := res.Current.Alerts; got < 15 || got > 21 {
		t.Errorf("current alerts = %d, want ~18 (suppressed per code per 10m)", got)
	}
	if r := res.Current.Rules[0]; r.Suppressed == 0 || len(r.Samples) != dryRunSamples {
		t.Errorf("current rule = %+v", r)
	}
	if len(res.Files) != 1 || res.Files[0].Estimated || res.Files[0].Lines == 0 {
		t.Errorf("files = %+v", res.Files)
	}

	res, err = a.DryRun(context.Background(), cand, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Candidate.Alerts; got < 59 || got > 61 {
		t.Errorf("30m window: candidate alerts = %d, want ~60", got)
	}
}

func TestDryRunWithoutHistoryAndBusy(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "new.log")
	os.WriteFile(logPath, []byte("ok\nFATAL one\nFATAL two\npartial FATAL"), 0o644)
	a, _ := testAgent(t, "")
	cand, err := rules.ParseWith([]byte(fmt.Sprintf("webhooks: [{name: h, url: '${NOT_SET_HERE}'}]\nrules:\n  - name: fatal\n    files: [%q]\n    pattern: FATAL\n    webhooks: [h]\n", logPath)), rules.Options{AllowUnresolvedEnv: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.DryRun(context.Background(), cand, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Files[0].Estimated || res.Candidate.Alerts != 2 || res.Current.Alerts != 0 {
		t.Errorf("result = %+v", res)
	}

	a.dryRuns <- struct{}{}
	if _, err := a.DryRun(context.Background(), cand, time.Hour); err != ErrDryRunBusy {
		t.Errorf("err = %v, want busy", err)
	}
	<-a.dryRuns
}

func TestOffsetHistResetsOnRotation(t *testing.T) {
	var h offsetHist
	for i := 0; i < histSize+5; i++ {
		h.add(offsetSample{int64(i), int64(i * 10)})
	}
	s := h.samples()
	if len(s) != histSize || s[0].t != 5 || s[len(s)-1].t != int64(histSize+4) {
		t.Fatalf("samples = %d, first %v", len(s), s[0])
	}
	h.add(offsetSample{1000, 3}) // file shrank: rotated
	if s := h.samples(); len(s) != 1 || s[0].off != 3 {
		t.Errorf("after rotation = %v", s)
	}
}

func TestLocalOverlay(t *testing.T) {
	base := "webhooks: [{name: h, url: 'http://127.0.0.1:1/x'}]\nrules:\n  - {name: group-rule, files: [/tmp/a.log], pattern: ERROR, webhooks: [h]}\n"
	a, dir := testAgent(t, base)

	local := "rules:\n  - {name: vm-extra, files: [/tmp/b.log], pattern: PANIC, webhooks: [h]}\n"
	if err := a.ApplyLocalRules([]byte(local), "test"); err != nil {
		t.Fatal(err)
	}
	if n := len(a.Active().Rules); n != 2 {
		t.Fatalf("active rules = %d, want 2", n)
	}
	st := a.Status()
	if st.LocalRules != 1 || st.RulesHash != rules.Hash([]byte(base)) || !st.Rules[1].Local || st.Rules[0].Local {
		t.Errorf("status = local %d hash %s rules %+v", st.LocalRules, st.RulesHash, st.Rules)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "rules.local.yaml")); string(got) != local {
		t.Errorf("local file = %q", got)
	}

	// A local rule may not replace a group rule.
	clash := "rules:\n  - {name: group-rule, files: [/tmp/b.log], pattern: x, webhooks: [h]}\n"
	if err := a.ApplyLocalRules([]byte(clash), "test"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("clash err = %v", err)
	}
	if n := len(a.Active().Rules); n != 2 {
		t.Errorf("after rejected overlay, active rules = %d, want 2", n)
	}

	// The group later adds a rule with the overlay's name: the group wins,
	// the overlay is reported as rejected.
	base2 := base + "  - {name: vm-extra, files: [/tmp/c.log], pattern: OOM, webhooks: [h]}\n"
	if _, _, err := a.ApplyRules([]byte(base2), "group:test"); err != nil {
		t.Fatal(err)
	}
	if st := a.Status(); st.LocalRulesError == "" || len(st.Rules) != 2 || st.Rules[1].Pattern != "OOM" {
		t.Errorf("status after group clash = %+v", st)
	}

	// Removing the overlay.
	if err := a.ApplyLocalRules(nil, "test"); err != nil {
		t.Fatal(err)
	}
	if st := a.Status(); st.LocalRulesHash != "" || st.LocalRulesError != "" {
		t.Errorf("status after removal = %+v", st)
	}
}
