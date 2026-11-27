package awsexport

import (
	"strings"
	"testing"
)

func TestTF1_TunedGolden(t *testing.T) {
	d, err := build(t, "tunedaws", Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := HCL(d, "eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "tunedaws.tf", b)
	s := string(b)
	for _, want := range []string{
		`resource "aws_wafv2_web_acl" "waf_tunedaws" {`,
		"default_action {\n    allow {}\n  }",
		`cloudwatch_metrics_enabled = true`,
		"rule_action_override {\n          name = \"SizeRestrictions_BODY\"",
		"scope_down_statement {\n          not_statement {\n            statement {\n              byte_match_statement {",
		"and_statement {\n        statement {\n          label_match_statement {",
		`regex_string = "^/web/(dataset|webclient)/"`,
		"# manual step: Set the ALB WAF body inspection limit to 16 KB",
		`count        = var.alb_arn == "" ? 0 : 1`,
		`version = "~> 6.0"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestTF2_TemplateEscaping(t *testing.T) {
	d, err := build(t, "rated", Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := HCL(d, "eu-central-1")
	s := string(b)
	if !strings.Contains(s, `= "$${jndi"`) || strings.Contains(s, `"${jndi"`) {
		t.Errorf("${ not escaped:\n%s", s)
	}
	for in, want := range map[string]string{`a%{b`: `"a%%{b"`, `x"y\z`: `"x\"y\\z"`, "${a}%{b}": `"$${a}%%{b}"`} {
		if got := hclString(in); got != want {
			t.Errorf("hclString(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestTF3_IPSetReferenceExpression(t *testing.T) {
	d, err := build(t, "rated", Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := HCL(d, "eu-central-1")
	s := string(b)
	for _, want := range []string{
		"arn = aws_wafv2_ip_set.waf_rated_OfficeAllow_v4.arn",
		"arn = aws_wafv2_ip_set.waf_rated_OfficeAllow_v6.arn",
		`resource "aws_wafv2_ip_set" "waf_rated_OfficeAllow_v6" {`,
		`addresses          = ["203.0.113.200/32", "198.51.100.7/32"]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(s, "arn:aws:wafv2") || strings.Contains(s, "Replace the IP set ARNs") {
		t.Errorf("placeholder ARN or JSON-only manual step in HCL")
	}
}
