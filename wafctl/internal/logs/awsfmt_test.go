package logs

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func fixtureEvent(action, rule, typ string, status int) Event {
	return Event{TS: "2026-11-27 10:00:00.123", RequestID: "rid1", NodeID: "n1", SiteID: "demo", ClientIP: "2001:db8::1",
		Country: "GB", Method: "POST", HTTPVersion: "HTTP/1.1", Path: "/api", Query: "a=1", Status: status, Action: action,
		TerminatingRule: rule, TerminatingType: typ, Labels: []string{"awswaf:managed:aws:core-rule-set:SizeRestrictions_Body"},
		RequestHeaders: map[string]string{"User-Agent": "x", "Host": "demo.lab.test"}}
}

func TestX1_ToAWSGolden(t *testing.T) {
	cases := map[string]struct {
		ev Event
		ms []Match
	}{
		"crs-block-kbi-count": {fixtureEvent("BLOCK", "AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY", "MANAGED_RULE_GROUP", 403), []Match{
			{RuleName: "SizeRestrictions_BODY", RuleGroup: "AWSManagedRulesCommonRuleSet", ConfiguredAction: "BLOCK", InScope: 1},
			{RuleName: "NoUserAgent_HEADER", RuleGroup: "AWSManagedRulesCommonRuleSet", ConfiguredAction: "COUNT", InScope: 1},
			{RuleName: "Log4JRCE_BODY", RuleGroup: "AWSManagedRulesKnownBadInputsRuleSet", ConfiguredAction: "COUNT", InScope: 1},
			{RuleName: "GenericRFI_BODY", RuleGroup: "AWSManagedRulesCommonRuleSet", ConfiguredAction: "BLOCK", InScope: 1, PostTerminating: 1},
			{RuleName: "GenericLFI_BODY", RuleGroup: "AWSManagedRulesCommonRuleSet", ConfiguredAction: "COUNT", InScope: 0},
		}},
		"custom-block": {fixtureEvent("BLOCK", "custom:tuned/BlockLargeBodyOutsideRpc", "REGULAR", 403), []Match{
			{RuleName: "SizeRestrictions_BODY", RuleGroup: "AWSManagedRulesCommonRuleSet", ConfiguredAction: "COUNT", InScope: 1},
			{RuleName: "BlockLargeBodyOutsideRpc", RuleGroup: "custom:tuned", ConfiguredAction: "BLOCK", InScope: 1},
		}},
		"default-allow": {fixtureEvent("ALLOW", "Default_Action", "DEFAULT", 200), nil},
	}
	for name, c := range cases {
		b, err := json.MarshalIndent(ToAWS(c.ev, c.ms), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, '\n')
		path := "testdata/aws-" + name + ".json"
		if *update {
			os.WriteFile(path, b, 0o644)
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, want) {
			t.Errorf("%s: golden mismatch\n%s", name, b)
		}
	}
	l := ToAWS(cases["crs-block-kbi-count"].ev, cases["crs-block-kbi-count"].ms)
	if len(l.RuleGroupList) != 2 || l.RuleGroupList[0].TerminatingRule == nil || l.RuleGroupList[1].TerminatingRule != nil ||
		len(l.RuleGroupList[0].NonTerminatingMatchingRules) != 1 || *l.ResponseCodeSent != 403 || l.Timestamp != 1795773600123 {
		t.Errorf("structure: %+v", l)
	}
	if d := ToAWS(cases["default-allow"].ev, nil); d.ResponseCodeSent != nil || d.TerminatingRuleID != "Default_Action" {
		t.Errorf("default allow: %+v", d)
	}
}

func TestX2_CSVHeader(t *testing.T) {
	cols, err := CSVColumns()
	if err != nil {
		t.Fatal(err)
	}
	want := "ts,request_id,node_id,site_id,app,host,client_ip,client_port,peer_ip,country,asn,as_org,method,scheme,http_version,tls_protocol,uri,path,query,status,bytes_sent,request_length,request_time,upstream_time,upstream_status,upstream_addr,user_agent,referer,content_type,content_length,user_class,rate_limit_status,waf_inspected,waf_mode,action,shadow_action,terminating_rule_id,terminating_rule,terminating_type,aws_default_action,aws_default_rule,labels,match_count,fail_reason"
	if got := strings.Join(cols, ","); got != want {
		t.Errorf("csv header:\n got %s\nwant %s", got, want)
	}
}
