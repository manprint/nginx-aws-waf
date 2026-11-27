package render

import (
	"strings"
	"testing"

	"nginxawswaf/wafctl/internal/config"
)

func TestR9_GoldenNginx(t *testing.T) {
	out := renderDir(t, fixtureDir)
	golden(t, "testdata/golden/nginx/nginx.conf", out.Files["nginx/nginx.conf"])
	for _, s := range fixtureSites {
		golden(t, "testdata/golden/nginx/sites/"+s+".conf", out.Files["nginx/sites/"+s+".conf"])
		for _, f := range []string{"static/" + s + "/403.html", "static/" + s + "/500.html"} {
			if len(out.Files[f]) == 0 {
				t.Errorf("%s missing", f)
			}
		}
	}
	for _, f := range []string{"data/bad-bots.data", "meta.json", "rules-index.json"} {
		if len(out.Files[f]) == 0 {
			t.Errorf("%s missing", f)
		}
	}
	if !strings.Contains(string(out.Files["meta.json"]), `"config_rev":"`+out.Rev+`"`) {
		t.Errorf("meta.json config_rev wrong")
	}
	ng := string(out.Files["nginx/nginx.conf"])
	for _, want := range []string{"resolver 127.0.0.11", `map "" $waf_node { default "lab-node-1"; }`, "listen 8080 default_server;", "listen [::]:8080 default_server;", "return 444;", "/etc/waf/runtime/" + out.Rev + "/modsec/main.conf"} {
		if !strings.Contains(ng, want) {
			t.Errorf("nginx.conf missing %q", want)
		}
	}
	demo := string(out.Files["nginx/sites/demo.conf"])
	for _, want := range []string{"server echo:8081 resolve;", "set_real_ip_from ::/0;", "modsecurity_rules_file /etc/waf/runtime/" + out.Rev + "/modsec/sites/demo.conf;", `more_set_headers "Server: awselb/2.0";`} {
		if !strings.Contains(demo, want) {
			t.Errorf("demo.conf missing %q", want)
		}
	}
}

func TestR10_RateZone(t *testing.T) {
	if got := RateZone("s", &config.RateLimit{Limit: 2000, WindowSec: 300}); !strings.Contains(got, "rate=400r/m;") {
		t.Errorf("got %s", got)
	}
	cfg, _ := config.Load(fixtureDir)
	cfg.Site("demo").RateLimit = &config.RateLimit{Limit: 2000, WindowSec: 300, Action: "count"}
	out, err := Render(cfg, testCat(t), nil, Options{Now: fixedNow, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.Files["nginx/nginx.conf"]), "zone=rl_demo:10m rate=400r/m;") {
		t.Errorf("zone missing")
	}
	s := string(out.Files["nginx/sites/demo.conf"])
	if !strings.Contains(s, "limit_req zone=rl_demo burst=2000 nodelay; limit_req_status 403;") || !strings.Contains(s, "limit_req_dry_run on;") {
		t.Errorf("limit_req lines missing:\n%s", s)
	}
}

func TestR11_TLSRedirect(t *testing.T) {
	cfg, _ := config.Load(fixtureDir)
	cfg.Site("demo").TLS = config.TLS{Mode: "redirect"}
	cfg.Node.DefaultSite = "demo"
	out, err := Render(cfg, testCat(t), nil, Options{Now: fixedNow, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out.Files["nginx/sites/demo.conf"])
	if n := strings.Count(s, "\nserver {"); n != 2 {
		t.Errorf("server blocks = %d, want 2:\n%s", n, s)
	}
	for _, want := range []string{"return 301 https://$host$request_uri;", "listen 8443 ssl default_server;", "listen 8080 default_server;", "ssl_certificate /etc/waf/certs/demo/fullchain.pem;", "http2 on;"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(string(out.Files["nginx/nginx.conf"]), "return 444") {
		t.Errorf("default server rendered although default_site is set")
	}
}

func TestR13_GeoBlockRender(t *testing.T) {
	cfg, _ := config.Load(fixtureDir)
	cfg.Node.GeoIP.Enabled = true
	cfg.Site("demo").GeoBlock = &config.GeoBlock{Countries: []string{"GB"}, Action: "block"}
	out, err := Render(cfg, testCat(t), nil, Options{Now: fixedNow, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.Files["modsec/main.conf"]), "SecGeoLookupDb /etc/waf/geoip/GeoLite2-Country.mmdb") {
		t.Errorf("SecGeoLookupDb missing")
	}
	main := string(out.Files["modsec/main.conf"])
	gb := strings.Index(main, "tag:'awswaf-rule:custom:demo/GeoBlock'")
	if gb < 0 || !strings.Contains(main, `SecRule TX:geo_cc "@rx ^(?:GB)$"`) {
		t.Fatalf("GeoBlock custom rule missing:\n%s", main)
	}
	// slot start: before the first managed group
	for _, g := range []string{"# ---- AWSManagedRulesAmazonIpReputationList", "# ---- AWSManagedRulesCommonRuleSet"} {
		if i := strings.Index(main, g); i < 0 || i < gb {
			t.Errorf("GeoBlock (at %d) not before %s (at %d)", gb, g, i)
		}
	}
}

func TestR14_RateLimitLabSite(t *testing.T) {
	cfg, _ := config.Load(fixtureDir)
	cfg.Site("demo").RateLimit = &config.RateLimit{Limit: 10, WindowSec: 60, Action: "block"}
	out, err := Render(cfg, testCat(t), nil, Options{Now: fixedNow, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.Files["nginx/nginx.conf"]), "limit_req_zone $binary_remote_addr zone=rl_demo:10m rate=10r/m;") {
		t.Errorf("zone missing")
	}
	s := string(out.Files["nginx/sites/demo.conf"])
	if !strings.Contains(s, "limit_req zone=rl_demo burst=10 nodelay; limit_req_status 403;") || strings.Contains(s, "limit_req_dry_run on;") {
		t.Errorf("limit_req lines:\n%s", s)
	}
}

func TestR15_IPMatchFullLengthPrefix(t *testing.T) {
	got := strings.Join(ipMatchList([]string{"203.0.113.200/32", "2001:db8::1/128", "2001:db8::/32", "10.0.0.0/8", "192.0.2.1"}), ",")
	if got != "203.0.113.200,2001:db8::1,2001:db8::/32,10.0.0.0/8,192.0.2.1" {
		t.Errorf("ipMatchList = %s", got)
	}
}
