package lists

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fetcher writes n entries per managed list (and a custom-reputation.txt that must be ignored).
func fetcher(n int, extra map[string]string) func(string) error {
	return func(out string) error {
		for _, name := range Managed {
			var b strings.Builder
			b.WriteString("# header 2026-11-27T00:00Z\n")
			for i := 0; i < n; i++ {
				fmt.Fprintf(&b, "198.18.%d.%d\n", i/250, i%250+1)
			}
			if err := os.WriteFile(filepath.Join(out, name), []byte(b.String()), 0o644); err != nil {
				return err
			}
		}
		for name, body := range extra {
			if err := os.WriteFile(filepath.Join(out, name), []byte(body), 0o644); err != nil {
				return err
			}
		}
		return nil
	}
}

func status(res []Result, list string) Result {
	for _, r := range res {
		if r.List == list {
			return r
		}
	}
	return Result{}
}

func TestLST1_HalfGuardAndForce(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Update(Options{ListsDir: dir, Fetch: fetcher(100, nil)}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, Managed[0]))
	res, changed, err := Update(Options{ListsDir: dir, Fetch: fetcher(10, nil)})
	if err != nil {
		t.Fatal(err)
	}
	r := status(res, Managed[0])
	if changed || r.Status != "kept" || r.Old != 100 || r.New != 10 {
		t.Fatalf("guard: changed=%v %+v", changed, r)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, Managed[0])); string(after) != string(before) {
		t.Errorf("guarded list was replaced")
	}
	res, changed, err = Update(Options{ListsDir: dir, Fetch: fetcher(10, nil), Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if r := status(res, Managed[0]); !changed || r.Status != "updated" || r.New != 10 {
		t.Fatalf("force: changed=%v %+v", changed, r)
	}
	res, changed, _ = Update(Options{ListsDir: dir, Fetch: fetcher(10, nil)})
	if r := status(res, Managed[0]); changed || r.Status != "unchanged" {
		t.Errorf("same content: changed=%v %+v", changed, r)
	}
	res, changed, _ = Update(Options{ListsDir: dir, Fetch: fetcher(5, nil)})
	if r := status(res, Managed[0]); !changed || r.Status != "updated" { // exactly 50 % is accepted
		t.Errorf("50%%: changed=%v %+v", changed, r)
	}
}

func TestLST2_InvalidCIDRNamesFileLine(t *testing.T) {
	dir := t.TempDir()
	bad := func(out string) error {
		if err := fetcher(3, nil)(out); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, "AnonymousIPList.txt"), []byte("# h\n192.0.2.1\n\n2001:db8::/32\n10.0.0.300/8\n"), 0o644)
	}
	_, changed, err := Update(Options{ListsDir: dir, Fetch: bad})
	if err == nil || !strings.Contains(err.Error(), "AnonymousIPList.txt:5:") || !strings.Contains(err.Error(), "10.0.0.300/8") {
		t.Fatalf("err %v", err)
	}
	if changed {
		t.Errorf("changed on error")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("files installed despite the invalid list: %v", ents)
	}
}

func TestLST3_CustomReputationUntouched(t *testing.T) {
	dir := t.TempDir()
	custom := "# operator\n203.0.113.0/24\n"
	if err := os.WriteFile(filepath.Join(dir, "custom-reputation.txt"), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _, err := Update(Options{ListsDir: dir, Fetch: fetcher(20, map[string]string{"custom-reputation.txt": "1.2.3.4\n", "custom-test.txt": "5.6.7.8\n"})})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "custom-reputation.txt")); string(b) != custom {
		t.Errorf("custom-reputation.txt changed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "custom-test.txt")); err == nil {
		t.Errorf("custom-test.txt installed")
	}
	if len(res) != len(Managed)+1 || status(res, "AnonymousIPList.txt").Status != "new" || status(res, "HostingProviderIPList.txt").Status != "created" {
		t.Errorf("results %+v", res)
	}
	// a new node: the missing custom list is created comment-only, then never rewritten
	dir2 := t.TempDir()
	if _, _, err := Update(Options{ListsDir: dir2, Fetch: fetcher(20, nil)}); err != nil {
		t.Fatal(err)
	}
	if e, _ := entries(filepath.Join(dir2, "custom-reputation.txt"), true); e != nil {
		t.Errorf("placeholder has entries %v", e)
	}
	os.WriteFile(filepath.Join(dir2, "custom-reputation.txt"), []byte(custom), 0o644)
	res, changed, _ := Update(Options{ListsDir: dir2, Fetch: fetcher(20, nil)})
	if b, _ := os.ReadFile(filepath.Join(dir2, "custom-reputation.txt")); string(b) != custom || changed || status(res, "custom-reputation.txt").Status != "" {
		t.Errorf("second run touched custom-reputation.txt: changed=%v %+v", changed, res)
	}
}
