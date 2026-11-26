package render

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"nginxawswaf/wafctl/internal/config"
)

const fixtureDir = "testdata/config"

var fixtureSites = []string{"allowlist", "demo", "shadow", "strict", "tuned"}

func TestR4_GoldenSites(t *testing.T) {
	out := renderDir(t, fixtureDir)
	for _, s := range fixtureSites {
		p := "modsec/sites/" + s + ".conf"
		b, ok := out.Files[p]
		if !ok {
			t.Fatalf("%s not rendered", p)
		}
		golden(t, "testdata/golden/sites/"+s+".conf", b)
	}
	golden(t, "testdata/golden/sites/main.conf", out.Files["modsec/main.conf"])
	dump(t, out)
}

func TestR5_NegatedCondition(t *testing.T) {
	cfg, err := config.Load(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	N := CustomRuleID(cfg.SiteIndex("tuned"), 0)
	main := string(renderDir(t, fixtureDir).Files["modsec/main.conf"])
	for _, want := range []string{
		fmt.Sprintf(`SecRule &TX:c%d_2 "@eq 0" "t:none,setvar:tx.hit_%d=1"`, N, N),
		fmt.Sprintf(`SecRule TX:c%d_1 "@eq 1" "t:none,chain"`, N),
		fmt.Sprintf(`SecRule TX:raw_path "@beginsWith /web/dataset/" "t:none,setvar:tx.c%d_2=1"`, N),
		fmt.Sprintf(`"id:%d,phase:2,pass,nolog,chain"`, N+8),
	} {
		if !strings.Contains(main, want) {
			t.Errorf("missing %s", want)
		}
	}
	// custom rule sits after the CRS group marker
	if strings.Index(main, fmt.Sprintf("id:%d,", N)) < strings.Index(main, "SecMarker END_GRP_CRS") {
		t.Errorf("custom rule not in slot after:AWSManagedRulesCommonRuleSet")
	}
}

func TestR6_GroupOverrideCount(t *testing.T) {
	cfg, err := config.Load(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	cat := testCat(t)
	s := cfg.Site("demo")
	s.RuleGroups = []config.RuleGroup{{Name: "AWSManagedRulesCommonRuleSet", OverrideAction: "count"}}
	out, err := Render(cfg, cat, nil, Options{Now: fixedNow, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	sf := string(out.Files["modsec/sites/demo.conf"])
	n := 0
	for _, r := range cat.GroupByKey("crs").Rules {
		has := strings.Contains(sf, fmt.Sprintf("setvar:tx.act_%d=count", r.ID))
		if r.DefaultAction == "block" {
			n++
			if !has {
				t.Errorf("rule %s not set to count", r.Name)
			}
		} else if has {
			t.Errorf("rule %s (default %s) should not be listed", r.Name, r.DefaultAction)
		}
	}
	if n == 0 {
		t.Fatal("no default-block CRS rules found")
	}
}

func TestR7_RulesIndex(t *testing.T) {
	cfg, _ := config.Load(fixtureDir)
	out := renderDir(t, fixtureDir)
	var idx map[string]IndexEntry
	if err := json.Unmarshal(out.Files["rules-index.json"], &idx); err != nil {
		t.Fatal(err)
	}
	for _, r := range testCat(t).Rules() {
		if _, ok := idx[strconv.Itoa(r.ID)]; !ok {
			t.Errorf("rule %d missing", r.ID)
		}
	}
	for site, name := range map[string]string{"allowlist": "AllowPublic", "tuned": "BlockLargeBodyOutsideRpc"} {
		e, ok := idx[strconv.Itoa(CustomRuleID(cfg.SiteIndex(site), 0))]
		if !ok || e.Name != name || e.Group != "custom:"+site || e.Site != site {
			t.Errorf("custom %s/%s entry = %+v", site, name, e)
		}
	}
}

func TestR8_TooManyConditions(t *testing.T) {
	cfg, _ := config.Load(fixtureDir)
	var conds []config.Cond
	for i := 0; i < 7; i++ {
		conds = append(conds, config.Cond{Method: []string{"GET"}})
	}
	cfg.Site("demo").CustomRules = []config.CustomRule{{Name: "Seven", Slot: "start", Action: "block", Match: config.Match{All: conds}}}
	_, err := Render(cfg, testCat(t), nil, Options{Now: fixedNow, Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "exceed the maximum of 6") {
		t.Errorf("err = %v", err)
	}
}
