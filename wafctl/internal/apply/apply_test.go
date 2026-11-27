package apply

import (
	"strings"

	"errors"
	"fmt"
	"nginxawswaf/wafctl/internal/render"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeEngine struct {
	running bool
	testErr error
	calls   []string
	rev     string
}

func (f *fakeEngine) Running(string) (bool, error) { return f.running, nil }
func (f *fakeEngine) Exec(_ string, a ...string) (string, error) {
	f.calls = append(f.calls, fmt.Sprint("exec ", a))
	if a[1] == "-t" {
		return "nginx: [emerg] bogus", f.testErr
	}
	if a[0] == "wget" {
		return f.rev, nil
	}
	return "", nil
}
func (f *fakeEngine) RunOnce(s string, a ...string) (string, error) { return f.Exec(s, a...) }
func (f *fakeEngine) Up() error                                     { f.calls = append(f.calls, "up"); return nil }
func (f *fakeEngine) Health(string) (string, error)                 { return "healthy", nil }
func (f *fakeEngine) Restart(s string) error                        { f.calls = append(f.calls, "restart "+s); return nil }

func prepared(t *testing.T) *Prepared {
	t.Helper()
	t.Setenv("WAF_DATA_DIR", t.TempDir())
	p, err := Prepare("../render/testdata/config", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestA1_FailedTestKeepsCurrent(t *testing.T) {
	p := prepared(t)
	rt := t.TempDir()
	if err := os.Mkdir(filepath.Join(rt, "20250101T000000Z-aaaaaaaa"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("20250101T000000Z-aaaaaaaa", filepath.Join(rt, "current")); err != nil {
		t.Fatal(err)
	}
	eng := &fakeEngine{running: true, testErr: errors.New("exit 1")}
	if _, err := Apply(p, eng, rt, Options{}); err == nil {
		t.Fatal("apply succeeded with failing nginx -t")
	}
	if cur, _ := os.Readlink(filepath.Join(rt, "current")); cur != "20250101T000000Z-aaaaaaaa" {
		t.Errorf("current = %s", cur)
	}
	if _, err := os.Stat(filepath.Join(rt, p.Out.Rev)); !os.IsNotExist(err) {
		t.Errorf("rev dir not removed: %v", err)
	}
	// success path: switches current and reloads
	eng.testErr = nil
	eng.rev = "/etc/waf/runtime/" + p.Out.Rev
	rev, err := Apply(p, eng, rt, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if cur, _ := os.Readlink(filepath.Join(rt, "current")); cur != rev {
		t.Errorf("current = %s, want %s", cur, rev)
	}
}

func TestA2_PruneKeepsFive(t *testing.T) {
	rt := t.TempDir()
	var revs []string
	for i := 1; i <= 8; i++ {
		r := fmt.Sprintf("2026010%dT000000Z-0000000%d", i, i)
		revs = append(revs, r)
		if err := os.Mkdir(filepath.Join(rt, r), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Symlink(revs[0], filepath.Join(rt, "current")) // oldest is current
	if err := Prune(rt, 5); err != nil {
		t.Fatal(err)
	}
	for i, r := range revs {
		_, err := os.Stat(filepath.Join(rt, r))
		keep := i == 0 || i >= 3
		if keep != (err == nil) {
			t.Errorf("rev %s kept=%v, want %v", r, err == nil, keep)
		}
	}
}

func TestB2_BypassRendersCount(t *testing.T) {
	p := prepared(t)
	out, err := render.Render(p.Cfg, p.Cat, map[string]bool{"demo": true}, render.Options{Now: time.Now(), Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(out.Files["modsec/sites/demo.conf"]); !strings.Contains(s, "setvar:tx.mode=count") {
		t.Errorf("demo not in count mode:\n%s", s)
	}
	if s := string(out.Files["modsec/sites/tuned.conf"]); !strings.Contains(s, "setvar:tx.mode=enforce") {
		t.Errorf("tuned affected by demo bypass")
	}
}

func TestA3_ReloadNotLoadedRestoresCurrent(t *testing.T) {
	p := prepared(t)
	rt := t.TempDir()
	old := "20250101T000000Z-aaaaaaaa"
	os.Mkdir(filepath.Join(rt, old), 0o755)
	os.Symlink(old, filepath.Join(rt, "current"))
	eng := &fakeEngine{running: true, rev: "/etc/waf/runtime/" + old} // workers keep serving the old rev
	_, err := Apply(p, eng, rt, Options{})
	if err == nil || !strings.Contains(err.Error(), "current restored to "+old) {
		t.Fatalf("err %v", err)
	}
	if got, _ := os.Readlink(filepath.Join(rt, "current")); got != old {
		t.Errorf("current -> %s, want %s", got, old)
	}
}
