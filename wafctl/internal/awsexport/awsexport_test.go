package awsexport

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
)

var update = flag.Bool("update", false, "rewrite golden files")

func build(t *testing.T, site string, opt Options) (*Document, error) {
	t.Helper()
	cp, err := env.CatalogPath()
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(cp)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load("testdata/config")
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range config.Validate(cfg, cat) {
		if is.Severity == "error" {
			t.Fatalf("fixture invalid: %s %s %s", is.File, is.Path, is.Msg)
		}
	}
	e, err := config.Effective(cfg, site, cat, false)
	if err != nil {
		t.Fatal(err)
	}
	return Build(e, cat, opt)
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name)
	if *update {
		os.WriteFile(p, got, 0o644)
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("%s differs from golden (go test -update):\n%s", name, got)
	}
}

func rules(d *Document) []M { return d.WebACL["Rules"].([]M) }

func TestEXP1_ProfileOnlySite(t *testing.T) {
	d, err := build(t, "plain", Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := JSON(d, false)
	golden(t, "plain.json", b)
	rs := rules(d)
	if len(rs) != 3 {
		t.Fatalf("%d rules", len(rs))
	}
	for i, n := range []string{"AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet"} {
		mrg := rs[i]["Statement"].(M)["ManagedRuleGroupStatement"].(M)
		if rs[i]["Priority"] != i*10 || mrg["Name"] != n || mrg["RuleActionOverrides"] != nil || mrg["ScopeDownStatement"] != nil {
			t.Errorf("rule %d: %v", i, rs[i])
		}
	}
	if len(d.Lossy) != 0 || len(d.IPSets) != 0 || strings.Join(d.ManualSteps, "|") != stepAssociate {
		t.Errorf("lossy %v ipsets %v steps %v", d.Lossy, d.IPSets, d.ManualSteps)
	}
}

func TestEXP2_TunedOverridesScopeDownCustom(t *testing.T) {
	d, err := build(t, "tunedaws", Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := JSON(d, false)
	golden(t, "tunedaws.json", b)
	rs := rules(d)
	var names []string
	for _, r := range rs {
		names = append(names, r["Name"].(string))
	}
	if strings.Join(names, ",") != "AWS-AWSManagedRulesAmazonIpReputationList,AWS-AWSManagedRulesCommonRuleSet,BlockLargeBodyOutsideRpc,AWS-AWSManagedRulesKnownBadInputsRuleSet" {
		t.Errorf("order %v", names)
	}
	s := string(b)
	for _, want := range []string{`"Name": "SizeRestrictions_BODY"`, `"PositionalConstraint": "STARTS_WITH"`, `"SearchString": "/static-ok/"`,
		`"RegexString": "^/web/(dataset|webclient)/"`, `"Type": "URL_DECODE_UNI"`, `"Type": "LOWERCASE"`,
		"Set the ALB WAF body inspection limit to 16 KB"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
	kbi := rs[3]["Statement"].(M)["ManagedRuleGroupStatement"].(M)
	if _, ok := kbi["ScopeDownStatement"].(M)["NotStatement"]; !ok {
		t.Errorf("scope-down not a NotStatement: %v", kbi["ScopeDownStatement"])
	}
	cust := rs[2]["Statement"].(M)["AndStatement"].(M)["Statements"].([]M)
	if _, ok := cust[0]["LabelMatchStatement"]; !ok {
		t.Errorf("custom[0] %v", cust[0])
	}
	if _, ok := cust[1]["NotStatement"].(M)["Statement"].(M)["RegexMatchStatement"]; !ok {
		t.Errorf("custom[1] %v", cust[1])
	}
}

func TestEXP3_LossyNeedsFlag(t *testing.T) {
	_, err := build(t, "lossy", Options{})
	var le *LossyError
	if !errors.As(err, &le) || strings.Join(le.Reasons, ",") != "client_ip.source=xff,path_overrides" {
		t.Fatalf("err %v", err)
	}
	if !strings.Contains(err.Error(), "--allow-lossy") {
		t.Errorf("message %v", err)
	}
	d, err := build(t, "lossy", Options{AllowLossy: true})
	if err != nil || strings.Join(d.Lossy, ",") != "client_ip.source=xff,path_overrides" {
		t.Errorf("lossy export: %v %v", d, err)
	}
	if b, _ := JSON(d, false); strings.Contains(string(b), "files") {
		t.Errorf("path override leaked into the export")
	}
}

func TestEXP4_MethodsOr(t *testing.T) {
	d, err := build(t, "methods", Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := rules(d)[0]
	and := r["Statement"].(M)["AndStatement"].(M)["Statements"].([]M)
	or := and[0]["OrStatement"].(M)["Statements"].([]M)
	if r["Name"] != "BlockWriteOnApi" || r["Priority"] != 0 || len(or) != 2 {
		t.Fatalf("rule %v", r)
	}
	for i, m := range []string{"PUT", "DELETE"} {
		bm := or[i]["ByteMatchStatement"].(M)
		if bm["SearchString"] != m || bm["PositionalConstraint"] != "EXACTLY" {
			t.Errorf("method %d: %v", i, bm)
		}
		if _, ok := bm["FieldToMatch"].(M)["Method"]; !ok {
			t.Errorf("method field %v", bm)
		}
	}
	if _, ok := r["Action"].(M)["Block"]; !ok {
		t.Errorf("action %v", r["Action"])
	}
}

func TestEXP5_ShadowAllCount(t *testing.T) {
	d, err := build(t, "shadowed", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules(d) {
		a := r["Action"]
		if a == nil {
			a = r["OverrideAction"]
		}
		if _, ok := a.(M)["Count"]; !ok || len(a.(M)) != 1 {
			t.Errorf("%s: %v", r["Name"], a)
		}
	}
	if _, ok := d.WebACL["DefaultAction"].(M)["Allow"]; !ok {
		t.Errorf("default action %v", d.WebACL["DefaultAction"])
	}
}

func TestEXP6_RateFirst(t *testing.T) {
	d, err := build(t, "rated", Options{Region: "eu-south-1", Account: "123456789012"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := JSON(d, false)
	golden(t, "rated.json", b)
	rs := rules(d)
	var names []string
	for _, r := range rs {
		names = append(names, r["Name"].(string))
	}
	if strings.Join(names, ",") != "RateLimit,GeoBlock,OfficeAllow,AWS-AWSManagedRulesAmazonIpReputationList,AWS-AWSManagedRulesCommonRuleSet,AWS-AWSManagedRulesKnownBadInputsRuleSet,BigHeader" {
		t.Errorf("order %v", names)
	}
	rb := rs[0]["Statement"].(M)["RateBasedStatement"].(M)
	if rb["Limit"] != 2000 || rb["EvaluationWindowSec"] != 300 || rb["AggregateKeyType"] != "IP" || rs[0]["Priority"] != 0 {
		t.Errorf("rate %v", rs[0])
	}
	if len(d.IPSets) != 2 || d.IPSets[0]["Name"] != "waf-rated-OfficeAllow-v4" || d.IPSets[1]["IPAddressVersion"] != "IPV6" {
		t.Errorf("ip sets %v", d.IPSets)
	}
	j, _ := json.Marshal(d.IPSets[0]["Addresses"])
	if string(j) != `["203.0.113.200/32","198.51.100.7/32"]` {
		t.Errorf("v4 addresses %s", j)
	}
	if !strings.Contains(string(b), "arn:aws:wafv2:eu-south-1:123456789012:regional/ipset/waf-rated-OfficeAllow-v6/00000000-0000-0000-0000-000000000000") ||
		!strings.Contains(strings.Join(d.ManualSteps, "|"), "Replace the IP set ARNs") {
		t.Errorf("arn/manual step")
	}
}
