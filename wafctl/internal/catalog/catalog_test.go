package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const catPath = "../../../waf/catalog/rules.yaml"

func TestCAT1_CatalogShape(t *testing.T) {
	c, err := Load(catPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Groups) != 11 {
		t.Fatalf("groups = %d, want 11", len(c.Groups))
	}
	var all, nonopt []string
	for _, g := range c.Groups {
		all = append(all, g.Key)
		if !g.Optional {
			nonopt = append(nonopt, g.Key)
		}
	}
	if got := strings.Join(all, ","); got != "iprep,anonip,crs,kbi,sqli,admin,linux,unix,windows,php,wordpress" {
		t.Errorf("order = %s", got)
	}
	if got := strings.Join(nonopt, ","); got != "iprep,crs,kbi" {
		t.Errorf("non-optional = %s", got)
	}
	want := map[string]int{"iprep": 3, "anonip": 2, "crs": 22, "kbi": 20, "sqli": 8,
		"admin": 1, "linux": 3, "unix": 3, "windows": 8, "php": 8, "wordpress": 2}
	total := 0
	for _, g := range c.Groups {
		if len(g.Rules) != want[g.Key] {
			t.Errorf("%s rules = %d, want %d", g.Key, len(g.Rules), want[g.Key])
		}
		total += len(g.Rules)
	}
	if total != 80 {
		t.Errorf("total = %d, want 80", total)
	}
	if r := c.RuleByName("AWSManagedRulesCommonRuleSet", "NoUserAgent_HEADER"); r == nil || r.ID != 1200010 {
		t.Errorf("NoUserAgent_HEADER = %+v", r)
	}
	if r := c.RuleByID(1300050); r == nil || FullLabel(r) != "awswaf:managed:aws:known-bad-inputs:Host_Localhost_Header" {
		t.Errorf("1300050 label wrong: %+v", r)
	}
	stubs := 0
	for _, r := range c.GroupByKey("kbi").Rules {
		if len(r.Detectors) == 0 {
			stubs++
		}
	}
	if stubs != 8 {
		t.Errorf("kbi stubs = %d, want 8", stubs)
	}
	if BaseID(c.GroupByKey("crs")) != 1200000 {
		t.Errorf("BaseID crs = %d", BaseID(c.GroupByKey("crs")))
	}
	if r := c.RuleByLabel("awswaf:managed:aws:core-rule-set:NoUserAgent_Header"); r == nil || r.ID != 1200010 {
		t.Errorf("RuleByLabel = %+v", r)
	}
}

func TestCAT2_LoadErrors(t *testing.T) {
	dir := t.TempDir()
	base := `version: 1
groups:
  - key: g
    name: G
    vendor: AWS
    wcu: 1
    label_ns: "ns:"
    optional: false
    rules:
      - {id: 10, name: A, label: A, default_action: block, fidelity: exact, detectors: []}
      - {id: %s, name: B, label: B, default_action: block, fidelity: exact, detectors: []%s}
`
	cases := []struct{ id, extra, want string }{
		{"10", "", "duplicate id"},
		{"20", ", bogus: 1", "bogus"},
	}
	for _, tc := range cases {
		p := filepath.Join(dir, "c.yaml")
		body := strings.Replace(strings.Replace(base, "%s", tc.id, 1), "%s", tc.extra, 1)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("case %s: err = %v, want substring %q", tc.want, err, tc.want)
		}
	}
}

func TestCAT3_MarkdownHeader(t *testing.T) {
	cat, err := Load("../../../waf/catalog/rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	WriteMarkdown(&b, cat.Rules())
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if lines[0] != "| ID | Group | Rule | Default | Fidelity | Detectors(vars → op) |" {
		t.Errorf("header = %q", lines[0])
	}
	if len(lines) != 2+len(cat.Rules()) {
		t.Errorf("lines = %d, rules = %d", len(lines), len(cat.Rules()))
	}
	if !strings.Contains(b.String(), "| 1200010 | crs | NoUserAgent_HEADER | block |") {
		t.Error("NoUserAgent row missing")
	}
}
