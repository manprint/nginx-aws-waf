package render

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

const catPath = "../../../waf/catalog/rules.yaml"

var fixedNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func testCat(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load(catPath)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func renderDir(t *testing.T, dir string) *Output {
	t.Helper()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(cfg, testCat(t), nil, Options{Now: fixedNow, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// span returns the text from the first "# ---- " line to the last "SecMarker" line, inclusive.
func span(t *testing.T, s string) string {
	t.Helper()
	a := strings.Index(s, "# ---- ")
	b := strings.LastIndex(s, "SecMarker ")
	if a < 0 || b < 0 {
		t.Fatalf("span markers missing")
	}
	e := strings.IndexByte(s[b:], '\n')
	return s[a : b+e+1]
}

func golden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from golden (run go test -update to inspect)", path)
	}
}

func TestR1_ReferenceOracle(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("SKIP: python3 missing")
	}
	if err := exec.Command("python3", "-c", "import yaml").Run(); err != nil {
		t.Skip("SKIP: PyYAML missing")
	}
	abs, _ := filepath.Abs(catPath)
	cmd := exec.Command("python3", "../../../docs/plans/001_plan-nginx-aws-waf/snippets/reference-render.py", "anonip", "sqli", "admin", "linux", "unix", "windows", "php", "wordpress")
	cmd.Env = append(os.Environ(), "WAF_CATALOG="+abs)
	ref, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	out := renderDir(t, "testdata/nosites")
	R := "/etc/waf/runtime/" + out.Rev
	want := span(t, strings.ReplaceAll(string(ref), "/etc/waf/data/", R+"/data/"))
	got := span(t, string(out.Files["modsec/main.conf"]))
	if want != got {
		wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
		for i := range wl {
			if i >= len(gl) || wl[i] != gl[i] {
				g := "<EOF>"
				if i < len(gl) {
					g = gl[i]
				}
				t.Fatalf("line %d differs:\nwant %s\ngot  %s", i+1, wl[i], g)
			}
		}
		t.Fatalf("got has %d extra lines", len(gl)-len(wl))
	}
}

func TestR2_GoldenNoSites(t *testing.T) {
	out := renderDir(t, "testdata/nosites")
	if !regexp.MustCompile(`^20260102T030405Z-[0-9a-f]{8}$`).MatchString(out.Rev) {
		t.Errorf("rev = %s", out.Rev)
	}
	if strings.Contains(string(out.Files["modsec/main.conf"]), "/REV") {
		t.Errorf("placeholder left in output")
	}
	golden(t, "testdata/golden/nosites/main.conf", out.Files["modsec/main.conf"])
	dump(t, out)
}

// dump writes the output to $WAF_DUMP_DIR/<rev>/ for nginx -t (scripts/ngx-test.sh).
func dump(t *testing.T, out *Output) {
	t.Helper()
	d := os.Getenv("WAF_DUMP_DIR")
	if d == "" {
		return
	}
	for p, b := range out.Files {
		full := filepath.Join(d, out.Rev, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("dumped to %s", filepath.Join(d, out.Rev))
}

func TestR3_Counts(t *testing.T) {
	cat := testCat(t)
	s := string(renderDir(t, "testdata/nosites").Files["modsec/main.conf"])
	for _, r := range cat.Rules() {
		if !strings.Contains(s, "/"+r.Name+"'") && !strings.Contains(s, " "+r.Name+": stub") {
			t.Errorf("rule %s missing", r.Name)
		}
	}
	want9, want7 := 0, 0
	for _, g := range cat.Groups {
		for _, r := range g.Rules {
			if len(r.Detectors) > 0 {
				want7++
				if !g.Optional && r.DefaultAction == "block" {
					want9++
				}
			}
		}
	}
	if want9 != 36 || want7 != 71 {
		t.Errorf("catalog recount: B+9=%d B+7=%d", want9, want7)
	}
	n9 := len(regexp.MustCompile(`(?m)"id:1[0-4][0-9]{4}9,phase:2`).FindAllString(s, -1))
	n7 := len(regexp.MustCompile(`(?m)"id:1[0-4][0-9]{4}7,phase:2`).FindAllString(s, -1))
	if n9 != 36 || n7 != 71 {
		t.Errorf("rendered B+9=%d B+7=%d, want 36/71", n9, n7)
	}
	if n := strings.Count(s, "stub, no detector"); n != 9 {
		t.Errorf("stubs = %d", n)
	}
	if regexp.MustCompile(`(?m)^\s+SecRule`).MatchString(s) {
		t.Errorf("indented SecRule found")
	}
	// audit.scope=relevant variant
	cfg, err := config.Load("testdata/nosites")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Node.Audit.Scope = "relevant"
	out, err := Render(cfg, cat, nil, Options{Now: fixedNow, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	rs := string(out.Files["modsec/main.conf"])
	if !strings.Contains(rs, "SecAuditEngine RelevantOnly") || !strings.Contains(rs, `"id:1900890,`) ||
		!strings.Contains(rs, `SecRule TX:relevant "@eq 1" "id:1900900,`) || strings.Contains(rs, `SecAction "id:1900900`) {
		t.Errorf("relevant variant wrong")
	}
}
