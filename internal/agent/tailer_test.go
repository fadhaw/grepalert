package agent

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type collector struct{ lines []string }

func (c *collector) add(_ string, l []byte) { c.lines = append(c.lines, string(l)) }

func newTestTailer(t *testing.T, path string, fromStart bool, maxLine int) (*tailer, *collector) {
	return newResumeTailer(t, path, fromStart, maxLine, nil)
}

func newResumeTailer(t *testing.T, path string, fromStart bool, maxLine int, resume *Position) (*tailer, *collector) {
	t.Helper()
	c := &collector{}
	tl := newTailer(path, time.Hour, maxLine, fromStart, resume, c.add,
		func(p string, err error) { t.Logf("tail error %s: %v", p, err) }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(tl.close)
	return tl, c
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func expectLines(t *testing.T, c *collector, want ...string) {
	t.Helper()
	if strings.Join(c.lines, "|") != strings.Join(want, "|") {
		t.Fatalf("lines = %q, want %q", c.lines, want)
	}
	c.lines = nil
}

func TestTailerStartsAtEndAndReadsPartialLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "old line\n")
	tl, c := newTestTailer(t, p, false, 1024)

	tl.step()
	expectLines(t, c)

	appendFile(t, p, "new 1\r\nnew ")
	tl.step()
	expectLines(t, c, "new 1")

	appendFile(t, p, "2\n")
	tl.step()
	expectLines(t, c, "new 2")
}

func TestTailerTruncation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "a\nb\n")
	tl, c := newTestTailer(t, p, true, 1024)
	tl.step()
	expectLines(t, c, "a", "b")

	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "c\n")
	tl.step()
	expectLines(t, c, "c")
}

func TestTailerRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendFile(t, p, "")
	tl, c := newTestTailer(t, p, false, 1024)
	tl.step()

	appendFile(t, p, "before\n")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	// Written to the old file after the rename but before we noticed.
	appendFile(t, p+".1", "late\n")
	tl.step() // file missing: keep reading old handle
	expectLines(t, c, "before", "late")

	appendFile(t, p, "after\n")
	tl.step()
	expectLines(t, c, "after")
}

func TestTailerFileCreatedLater(t *testing.T) {
	p := filepath.Join(t.TempDir(), "later.log")
	tl, c := newTestTailer(t, p, false, 1024)
	tl.step()
	appendFile(t, p, "first\n")
	tl.step()
	expectLines(t, c, "first")
}

func TestTailerLongLineIsTruncated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "")
	tl, c := newTestTailer(t, p, false, 10)
	tl.step()
	appendFile(t, p, strings.Repeat("x", 100000)+"\nshort\n")
	tl.step()
	expectLines(t, c, strings.Repeat("x", 10), "short")
	if cap(tl.lineBuf) > 64*1024 {
		t.Fatalf("line buffer grew to %d", cap(tl.lineBuf))
	}
}

// restart simulates stopping a tailer and starting a new one from its saved position.
func restart(t *testing.T, tl *tailer, path string) (*tailer, *collector) {
	t.Helper()
	pos := tl.position()
	if pos == nil {
		t.Fatal("no position saved")
	}
	tl.close()
	return newResumeTailer(t, path, false, 1024, pos)
}

func TestResumeAfterRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "old\n")
	tl, c := newTestTailer(t, p, false, 1024)
	tl.step()
	appendFile(t, p, "a\nb\npart")
	tl.step()
	expectLines(t, c, "a", "b")

	// Written while the agent is down, including the rest of a partial line.
	appendFile(t, p, "ial\nc\n")
	tl2, c2 := restart(t, tl, p)
	tl2.step()
	expectLines(t, c2, "partial", "c")
}

func TestResumeAfterRenameRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "")
	tl, c := newTestTailer(t, p, false, 1024)
	tl.step()
	appendFile(t, p, "seen\n")
	tl.step()
	expectLines(t, c, "seen")
	pos := tl.position()
	tl.close()

	// While stopped: more lines, then rotation, then lines in the new file.
	appendFile(t, p, "missed 1\nmissed 2")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p+".1.gz", "not a candidate\n")
	appendFile(t, p, "new 1\n")

	tl2, c2 := newResumeTailer(t, p, false, 1024, pos)
	tl2.step()
	expectLines(t, c2, "missed 1", "missed 2", "new 1")
}

func TestResumeAfterCopyTruncate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "")
	tl, c := newTestTailer(t, p, false, 1024)
	tl.step()
	appendFile(t, p, "seen\n")
	tl.step()
	expectLines(t, c, "seen")
	pos := tl.position()
	tl.close()

	appendFile(t, p, "missed\n")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+"-20261012", data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "after\n")

	tl2, c2 := newResumeTailer(t, p, false, 1024, pos)
	tl2.step()
	expectLines(t, c2, "missed", "after")
}

func TestResumeWhenFileReplacedAndOldOneGone(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "")
	tl, _ := newTestTailer(t, p, false, 1024)
	tl.step()
	appendFile(t, p, "original content that is long enough\n")
	tl.step()
	pos := tl.position()
	tl.close()

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "brand new file with more content than before, so it is larger\n")
	tl2, c2 := newResumeTailer(t, p, false, 1024, pos)
	tl2.step()
	expectLines(t, c2, "brand new file with more content than before, so it is larger")
}

func TestPositionKeptWhileFileMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gone.log")
	pos := &Position{Offset: 10, FP: "x", FPLen: 10}
	tl, _ := newResumeTailer(t, p, false, 1024, pos)
	tl.step()
	if got := tl.position(); got == nil || *got != *pos {
		t.Fatalf("position = %+v, want saved position kept", got)
	}
}

// tailerClock lets a test move a tailer's time forward.
func tailerClock(tl *tailer) *time.Time {
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	tl.now = func() time.Time { return now }
	return &now
}

// copytruncate, then a burst that makes the file larger than before, all
// between two steps: the size never looks smaller, but the head changed.
func TestTailerTruncatedAndRefilledBetweenSteps(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "")
	tl, c := newTestTailer(t, p, false, 1024)
	tl.step()
	appendFile(t, p, strings.Repeat("INFO request served in 12 ms ok\n", 3)) // 96 bytes
	tl.step()
	c.lines = nil

	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "ERROR payment failed order=1 (gateway)\n"+
		"ERROR payment failed order=2 (gateway)\n"+
		"ERROR payment failed order=3 (gateway)\n") // 117 bytes
	tl.step()
	expectLines(t, c,
		"ERROR payment failed order=1 (gateway)",
		"ERROR payment failed order=2 (gateway)",
		"ERROR payment failed order=3 (gateway)")
}

// nginx-style rotation: the file is renamed and recreated, but the program
// keeps writing to the renamed file until it reopens its log.
func TestTailerReadsOldFileAfterRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "access.log")
	appendFile(t, p, "")
	tl, c := newTestTailer(t, p, false, 1024)
	now := tailerClock(tl)
	tl.step()

	appendFile(t, p, "before\n")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "new 1\n")
	tl.step()
	expectLines(t, c, "before", "new 1")

	// Still written to the old file after the agent switched to the new one,
	// including a line in two parts, while the new file gets lines too.
	appendFile(t, p+".1", "GET /api/checkout 502\nhalf")
	tl.step()
	expectLines(t, c, "GET /api/checkout 502")
	appendFile(t, p+".1", " a line\n")
	appendFile(t, p, "new 2\n")
	tl.step()
	expectLines(t, c, "half a line", "new 2")

	// At the end of the grace period the old file is read a last time and closed.
	*now = now.Add(rotateGrace)
	appendFile(t, p+".1", "last\n")
	tl.step()
	expectLines(t, c, "last")
	if tl.old != nil {
		t.Fatal("old file still open after the grace period")
	}
	appendFile(t, p+".1", "too late\n")
	tl.step()
	expectLines(t, c)
}

// The unfinished last line of the old file must not be glued to the first
// line of the new one; it is emitted on its own when the old file is done.
func TestTailerRotationKeepsPartialLineApart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "")
	tl, c := newTestTailer(t, p, false, 1024)
	now := tailerClock(tl)
	tl.step()

	appendFile(t, p, "complete\nunfinished")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "first of new\n")
	tl.step()
	expectLines(t, c, "complete", "first of new")

	*now = now.Add(rotateGrace)
	tl.step()
	expectLines(t, c, "unfinished")
}

// A deleted file that is not recreated is let go after the grace period, so
// its disk space is freed, and picked up again from the start if it returns.
func TestTailerLetsGoOfDeletedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, p, "")
	tl, c := newTestTailer(t, p, false, 1024)
	now := tailerClock(tl)
	tl.step()
	appendFile(t, p, "last words\n")
	tl.step()
	expectLines(t, c, "last words")

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	tl.step()
	if tl.f == nil {
		t.Fatal("closed before the grace period ended")
	}
	*now = now.Add(rotateGrace)
	tl.step()
	if tl.f != nil {
		t.Fatal("deleted file still open after the grace period")
	}

	appendFile(t, p, "back\n")
	tl.step()
	expectLines(t, c, "back")
}
