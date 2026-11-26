package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeExec struct{ calls []string }

func (f *fakeExec) Exec(_ string, a ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(a, " "))
	return "", nil
}

func write(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Repeat("x", n)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestL0_Rotate(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	logs, raw := t.TempDir(), t.TempDir()
	write(t, filepath.Join(logs, "access.log"), 100)
	write(t, filepath.Join(logs, "audit.log"), 5)
	write(t, filepath.Join(logs, "audit.log.20261125T100000Z"), 1) // 26 h old → deleted
	write(t, filepath.Join(logs, "error.log.20261126T000000Z"), 1) // 12 h old → kept
	write(t, filepath.Join(raw, "2026-11-18", "events.jsonl"), 1)  // 8 days → deleted
	write(t, filepath.Join(raw, "2026-11-19", "events.jsonl"), 1)  // 7 days → kept
	write(t, filepath.Join(raw, "2026-11-26", "events.jsonl"), 1)
	f := &fakeExec{}
	reopened := 0
	rep, err := Rotate(logs, raw, f, Options{MaxSize: 10, KeepHours: 24, RawDays: 7, Now: now, ReopenAudit: func() error { reopened++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Rotated) != 1 || rep.Rotated[0] != "access.log.20261126T120000Z" {
		t.Errorf("rotated %v", rep.Rotated)
	}
	if exists(filepath.Join(logs, "access.log")) || !exists(filepath.Join(logs, "audit.log")) {
		t.Error("wrong files renamed")
	}
	if exists(filepath.Join(logs, "audit.log.20261125T100000Z")) || !exists(filepath.Join(logs, "error.log.20261126T000000Z")) {
		t.Error("rotated-file pruning by age wrong")
	}
	if exists(filepath.Join(raw, "2026-11-18")) || !exists(filepath.Join(raw, "2026-11-19")) || !exists(filepath.Join(raw, "2026-11-26")) {
		t.Error("raw pruning wrong")
	}
	if len(f.calls) != 1 || !strings.HasPrefix(f.calls[0], "nginx -s reopen") || reopened != 0 {
		t.Errorf("calls %v reopened %d (audit.log was not rotated)", f.calls, reopened)
	}
	// audit.log over the limit → ReopenAudit once
	write(t, filepath.Join(logs, "audit.log"), 100)
	if _, err := Rotate(logs, raw, &fakeExec{}, Options{MaxSize: 10, KeepHours: 24, RawDays: 7, Now: now.Add(time.Second), ReopenAudit: func() error { reopened++; return nil }}); err != nil || reopened != 1 {
		t.Errorf("reopened %d %v", reopened, err)
	}
	// nothing to rotate → no nginx signal
	f2 := &fakeExec{}
	if _, err := Rotate(logs, raw, f2, Options{MaxSize: 1 << 20, KeepHours: 24, RawDays: 7, Now: now}); err != nil || len(f2.calls) != 0 {
		t.Errorf("unexpected calls %v %v", f2.calls, err)
	}
	if n, err := ParseSize("512MiB"); err != nil || n != 512<<20 {
		t.Errorf("ParseSize %d %v", n, err)
	}
}
