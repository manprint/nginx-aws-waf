package config

import (
	"strings"
	"testing"
)

type vcase struct {
	name string
	mut  func(c *Config)
	want string // substring of an error message
}

func baseCfg() *Config {
	n := &Node{Version: 1, NodeID: "n1", File: "node.yaml"}
	n.applyDefaults()
	s := &Site{Version: 1, SiteID: "s1", ServerNames: []string{"s1.test"}, App: "generic",
		Upstream: Upstream{Servers: []string{"echo:8081"}}, TLS: TLS{Mode: "off"}, File: "sites/s1.yaml"}
	return &Config{Node: n, Sites: []*Site{s}, Profiles: map[string]*Profile{
		"aws-default": {Version: 1, Name: "aws-default", File: "profiles/aws-default.yaml"},
	}}
}

func runCases(t *testing.T, cases []vcase) {
	t.Helper()
	cat := testCat(t)
	if is := Validate(baseCfg(), cat); HasErrors(is) {
		t.Fatalf("base config not valid: %v", is)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseCfg()
			tc.mut(c)
			is := Validate(c, cat)
			for _, i := range is {
				if i.Severity == "error" && strings.Contains(i.Msg, tc.want) {
					return
				}
			}
			t.Errorf("want error containing %q, got %v", tc.want, is)
		})
	}
}

func s0(c *Config) *Site { return c.Sites[0] }

func TestVAL1_Node(t *testing.T) {
	runCases(t, []vcase{
		{"node_id", func(c *Config) { c.Node.NodeID = "Bad_ID" }, "node_id"},
		{"role", func(c *Config) { c.Node.Role = "x" }, "role"},
		{"network", func(c *Config) { c.Node.Network = "x" }, "network"},
		{"port", func(c *Config) { c.Node.Listen.HTTP = 70000 }, "out of range"},
		{"workers", func(c *Config) { c.Node.Workers = -1 }, "workers"},
		{"audit", func(c *Config) { c.Node.Audit.Scope = "x" }, "audit.scope"},
	})
}

func TestVAL2_SiteIdentity(t *testing.T) {
	runCases(t, []vcase{
		{"site_id", func(c *Config) { s0(c).SiteID = "Bad" }, "site_id"},
		{"server_names empty", func(c *Config) { s0(c).ServerNames = nil }, "server_names must not be empty"},
		{"server_name chars", func(c *Config) { s0(c).ServerNames = []string{"A_B"} }, "server name"},
		{"server_name dup", func(c *Config) {
			s2 := *s0(c)
			s2.SiteID = "s2"
			c.Sites = append(c.Sites, &s2)
		}, "already used"},
		{"app", func(c *Config) { s0(c).App = "x" }, "app"},
		{"upstream", func(c *Config) { s0(c).Upstream.Servers = []string{"nohost"} }, "host:port"},
		{"tls mode", func(c *Config) { s0(c).TLS.Mode = "x" }, "tls.mode"},
		{"tls files", func(c *Config) {
			t.Setenv("WAF_DATA_DIR", t.TempDir())
			s0(c).TLS.Mode = "on"
		}, "certificate file"},
	})
}

func TestVAL3_Enums(t *testing.T) {
	runCases(t, []vcase{
		{"mode", func(c *Config) { s0(c).Mode = "x" }, "mode"},
		{"default_action", func(c *Config) { s0(c).DefaultAction = "x" }, "default_action"},
		{"fail", func(c *Config) { s0(c).Fail.PCRELimit = "x" }, "fail.pcre_limit"},
		{"body_limit", func(c *Config) { s0(c).BodyLimit = 2000000 }, "body_limit"},
	})
}

func TestVAL4_ClientIP(t *testing.T) {
	runCases(t, []vcase{
		{"source", func(c *Config) { s0(c).ClientIP.Source = "x" }, "client_ip.source"},
		{"xff needs proxies", func(c *Config) { s0(c).ClientIP.Source = "xff" }, "requires trusted_proxies"},
		{"cidr", func(c *Config) { s0(c).ClientIP.TrustedProxies = []string{"10.0.0.0/33"} }, "invalid CIDR"},
		{"any only lab", func(c *Config) { s0(c).ClientIP.TrustedProxies = []string{"::/0"} }, "lab.enabled"},
	})
}

func TestVAL5_RuleGroups(t *testing.T) {
	runCases(t, []vcase{
		{"unknown group", func(c *Config) { s0(c).RuleGroups = []RuleGroup{{Name: "Nope"}} }, "unknown rule group"},
		{"override_action", func(c *Config) {
			s0(c).RuleGroups = []RuleGroup{{Name: "AWSManagedRulesCommonRuleSet", OverrideAction: "x"}}
		}, "override_action"},
		{"rule name", func(c *Config) {
			s0(c).RuleGroups = []RuleGroup{{Name: "AWSManagedRulesCommonRuleSet", RuleActionOverrides: map[string]string{"Nope": "count"}}}
		}, "is not in group"},
		{"rule action", func(c *Config) {
			s0(c).RuleGroups = []RuleGroup{{Name: "AWSManagedRulesCommonRuleSet", RuleActionOverrides: map[string]string{"NoUserAgent_HEADER": "x"}}}
		}, "not in {block,count,allow}"},
	})
}

func cr(m Match) []CustomRule {
	return []CustomRule{{Name: "R", Slot: "start", Action: "block", Match: m}}
}

func TestVAL6_CustomRules(t *testing.T) {
	runCases(t, []vcase{
		{"name", func(c *Config) {
			s0(c).CustomRules = []CustomRule{{Name: "bad name", Slot: "start", Action: "block", Match: Match{All: []Cond{{Method: []string{"GET"}}}}}}
		}, "name"},
		{"slot", func(c *Config) {
			s0(c).CustomRules = []CustomRule{{Name: "R", Slot: "after:AWSManagedRulesSQLiRuleSet", Action: "block", Match: Match{All: []Cond{{Method: []string{"GET"}}}}}}
		}, "slot"},
		{"action", func(c *Config) {
			s0(c).CustomRules = []CustomRule{{Name: "R", Slot: "start", Action: "x", Match: Match{All: []Cond{{Method: []string{"GET"}}}}}}
		}, "action"},
		{"empty match", func(c *Config) { s0(c).CustomRules = cr(Match{}) }, "match.all must not be empty"},
		{"two kinds", func(c *Config) {
			s0(c).CustomRules = cr(Match{All: []Cond{{Method: []string{"GET"}, Geo: []string{"IT"}}}})
		}, "exactly one condition kind"},
		{"label", func(c *Config) { s0(c).CustomRules = cr(Match{All: []Cond{{Label: "awswaf:nope"}}}) }, "unknown label"},
		{"label ns", func(c *Config) { s0(c).CustomRules = cr(Match{All: []Cond{{LabelNamespace: "nope:"}}}) }, "unknown label namespace"},
		{"method", func(c *Config) { s0(c).CustomRules = cr(Match{All: []Cond{{Method: []string{"get"}}}}) }, "uppercase"},
		{"ip_set", func(c *Config) { s0(c).CustomRules = cr(Match{All: []Cond{{IPSet: []string{"1.2.3"}}}}) }, "invalid CIDR"},
		{"geo needs geoip", func(c *Config) { s0(c).CustomRules = cr(Match{All: []Cond{{Geo: []string{"IT"}}}}) }, "geoip.enabled"},
		{"size", func(c *Config) {
			s0(c).CustomRules = cr(Match{All: []Cond{{Size: &Size{Component: "header:X Y", Op: "gt", Value: 1}}}})
		}, "component"},
		{"transform", func(c *Config) {
			s0(c).CustomRules = cr(Match{All: []Cond{{URIPath: &StrMatch{Exact: "/a", Transform: []string{"x"}}}}})
		}, "transform"},
		{"header name", func(c *Config) { s0(c).CustomRules = cr(Match{All: []Cond{{Header: &StrMatch{Exact: "a"}}}}) }, "name is required"},
	})
}

func TestVAL7_RateGeo(t *testing.T) {
	runCases(t, []vcase{
		{"limit", func(c *Config) { s0(c).RateLimit = &RateLimit{Limit: 5, WindowSec: 300, Action: "block"} }, "limit"},
		{"window", func(c *Config) { s0(c).RateLimit = &RateLimit{Limit: 100, WindowSec: 30, Action: "block"} }, "window_sec"},
		{"geo code", func(c *Config) {
			c.Node.GeoIP.Enabled = true
			s0(c).GeoBlock = &GeoBlock{Countries: []string{"ita"}, Action: "block"}
		}, "country code"},
	})
}

func TestVAL8_PathOverrides(t *testing.T) {
	runCases(t, []vcase{
		{"prefix", func(c *Config) {
			s0(c).PathOverrides = []PathOverride{{PathPrefix: "x", Rules: map[string]string{"NoUserAgent_HEADER": "count"}}}
		}, "path_prefix"},
		{"rule", func(c *Config) {
			s0(c).PathOverrides = []PathOverride{{PathPrefix: "/x", Rules: map[string]string{"Nope": "count"}}}
		}, "unknown rule"},
	})
}

func TestVAL9_SiteCount(t *testing.T) {
	runCases(t, []vcase{
		{"too many", func(c *Config) {
			for i := 0; i < MaxSites; i++ {
				s := *s0(c)
				s.SiteID = "x" + strings.Repeat("a", i%20) + string(rune('a'+i%26))
				s.ServerNames = nil
				c.Sites = append(c.Sites, &s)
			}
		}, "exceed the maximum"},
	})
}

func TestCMP1_Compat(t *testing.T) {
	cat := testCat(t)
	c := baseCfg()
	e, err := Effective(c, "s1", cat, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := Compat(e, cat); len(r) != 0 {
		t.Errorf("aws-default site reasons = %v", r)
	}
	s0(c).ClientIP = ClientIP{Source: "xff", TrustedProxies: []string{"10.0.0.0/8"}}
	e, _ = Effective(c, "s1", cat, false)
	r := Compat(e, cat)
	if len(r) != 1 || r[0] != "client_ip.source=xff" {
		t.Errorf("xff site reasons = %v", r)
	}
	s0(c).BodyLimit = 10000
	s0(c).PathOverrides = []PathOverride{{PathPrefix: "/a", Rules: map[string]string{"NoUserAgent_HEADER": "count"}}}
	e, _ = Effective(c, "s1", cat, false)
	if r := strings.Join(Compat(e, cat), "; "); !strings.Contains(r, "body_limit") || !strings.Contains(r, "path_overrides") {
		t.Errorf("reasons = %s", r)
	}
}
