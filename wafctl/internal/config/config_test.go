package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginxawswaf/wafctl/internal/catalog"
)

func testCat(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load("../../../waf/catalog/rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func loadTD(t *testing.T) *Config {
	t.Helper()
	cfg, err := Load("testdata")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func eff(t *testing.T, cfg *Config, id string, bypass bool) *EffectiveSite {
	t.Helper()
	e, err := Effective(cfg, id, testCat(t), bypass)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for p, body := range files {
		full := filepath.Join(d, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestCFG1_Defaults(t *testing.T) {
	cfg := loadTD(t)
	e := eff(t, cfg, "plain", false)
	if e.WAF.Mode != "enforce" || e.WAF.BodyLimit != 8192 || e.WAF.DefaultAction != "allow" {
		t.Errorf("defaults wrong: %+v", e.WAF)
	}
	var on []string
	for _, g := range e.WAF.RuleGroups {
		if *g.Enabled {
			on = append(on, g.Name)
		}
	}
	want := "AWSManagedRulesAmazonIpReputationList,AWSManagedRulesCommonRuleSet,AWSManagedRulesKnownBadInputsRuleSet"
	if got := strings.Join(on, ","); got != want {
		t.Errorf("enabled groups = %s", got)
	}
	if cfg.Site("plain").TLS.Mode != "off" {
		t.Errorf("tls.mode = %q, want off", cfg.Site("plain").TLS.Mode)
	}
	if cfg.Node.Listen.HTTP != 8080 || !*cfg.Node.Listen.IPv6 {
		t.Errorf("node defaults wrong: %+v", cfg.Node.Listen)
	}
	if strings.Join(e.ProfileChain, ",") != "aws-default" {
		t.Errorf("chain = %v", e.ProfileChain)
	}
}

func TestCFG2_ShadowProfile(t *testing.T) {
	e := eff(t, loadTD(t), "shadowed", false)
	if e.WAF.Mode != "count" || e.Origins["mode"] != "profile:shadow" {
		t.Errorf("mode=%s origin=%s", e.WAF.Mode, e.Origins["mode"])
	}
}

func TestCFG3_OverridesMerged(t *testing.T) {
	e := eff(t, loadTD(t), "merged", false)
	var crs *RuleGroup
	for i := range e.WAF.RuleGroups {
		if e.WAF.RuleGroups[i].Name == "AWSManagedRulesCommonRuleSet" {
			crs = &e.WAF.RuleGroups[i]
		}
	}
	if crs == nil || crs.RuleActionOverrides["SizeRestrictions_BODY"] != "count" || crs.RuleActionOverrides["NoUserAgent_HEADER"] != "count" {
		t.Fatalf("overrides = %+v", crs)
	}
	if e.Origins["rule:AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY"] != "profile:p-overrides" ||
		e.Origins["rule:AWSManagedRulesCommonRuleSet/NoUserAgent_HEADER"] != "site" {
		t.Errorf("origins = %v", e.Origins)
	}
}

func TestCFG4_CustomRuleReplace(t *testing.T) {
	e := eff(t, loadTD(t), "merged", false)
	if len(e.WAF.CustomRules) != 1 || e.WAF.CustomRules[0].Action != "block" ||
		e.WAF.CustomRules[0].Match.All[0].URIPath.StartsWith != "/site/" {
		t.Errorf("custom rules = %+v", e.WAF.CustomRules)
	}
}

func TestCFG5_ProfileCycle(t *testing.T) {
	d := writeFiles(t, map[string]string{
		"node.yaml":       "version: 1\nnode_id: n\n",
		"sites/s.yaml":    "version: 1\nsite_id: s\nserver_names: [s.test]\napp: generic\nprofile: a\nupstream: {servers: [\"x:1\"]}\n",
		"profiles/a.yaml": "version: 1\nname: a\nextends: b\n",
		"profiles/b.yaml": "version: 1\nname: b\nextends: a\n",
	})
	cfg, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Effective(cfg, "s", testCat(t), false)
	if err == nil || !strings.Contains(err.Error(), "profile cycle a->b->a") {
		t.Errorf("err = %v", err)
	}
}

func TestCFG6_UnknownKey(t *testing.T) {
	d := writeFiles(t, map[string]string{
		"node.yaml":    "version: 1\nnode_id: n\n",
		"sites/s.yaml": "version: 1\nsite_id: s\nbogus_key: 1\n",
	})
	_, err := Load(d)
	if err == nil || !strings.Contains(err.Error(), filepath.Join("sites", "s.yaml")) || !strings.Contains(err.Error(), "bogus_key") {
		t.Errorf("err = %v", err)
	}
}

func TestCFG7_Bypass(t *testing.T) {
	e := eff(t, loadTD(t), "plain", true)
	if e.WAF.Mode != "count" || e.Origins["mode"] != "bypass" {
		t.Errorf("mode=%s origin=%s", e.WAF.Mode, e.Origins["mode"])
	}
}
