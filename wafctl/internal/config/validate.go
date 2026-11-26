package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/env"
)

// Issue is one validation finding.
type Issue struct {
	File     string
	Path     string
	Msg      string
	Severity string // error | warning
}

func (i Issue) String() string {
	m := i.Msg
	if i.Severity == "warning" {
		m = "warning: " + m
	}
	return fmt.Sprintf("%s: %s: %s", i.File, i.Path, m)
}

// HasErrors reports whether any issue is an error.
func HasErrors(is []Issue) bool {
	for _, i := range is {
		if i.Severity == "error" {
			return true
		}
	}
	return false
}

// MaxSites is the per-node site limit (D23).
const MaxSites = 100

var (
	reNodeID     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reSiteID     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	reServerName = regexp.MustCompile(`^[a-z0-9*.-]+$`)
	reCustomName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	reMethod     = regexp.MustCompile(`^[A-Z]+$`)
	reGeo        = regexp.MustCompile(`^[A-Z]{2}$`)
	reSizeComp   = regexp.MustCompile(`^(body|query_string|uri_path|cookie|header:[A-Za-z0-9-]+)$`)
)

func in(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

type vctx struct {
	issues []Issue
	file   string
}

func (v *vctx) err(path, f string, a ...any) {
	v.issues = append(v.issues, Issue{v.file, path, fmt.Sprintf(f, a...), "error"})
}

func (v *vctx) warn(path, f string, a ...any) {
	v.issues = append(v.issues, Issue{v.file, path, fmt.Sprintf(f, a...), "warning"})
}

// Validate checks the node, every site and its effective WAF settings.
func Validate(cfg *Config, cat *catalog.Catalog) []Issue {
	v := &vctx{}
	n := cfg.Node
	v.file = n.File
	// rule 1: node
	if !reNodeID.MatchString(n.NodeID) {
		v.err("node_id", "node_id %q must match %s", n.NodeID, reNodeID)
	}
	if !in(n.Role, "node", "central", "all-in-one") {
		v.err("role", "role %q not in {node,central,all-in-one}", n.Role)
	}
	if !in(n.Network, "host", "bridge") {
		v.err("network", "network %q not in {host,bridge}", n.Network)
	}
	for k, p := range map[string]int{"listen.http": n.Listen.HTTP, "listen.https": n.Listen.HTTPS, "central.ingest_port": n.Central.IngestPort, "central.pki_port": n.Central.PKIPort} {
		if p < 1 || p > 65535 {
			v.err(k, "port %d out of range 1-65535", p)
		}
	}
	if n.Workers < 0 {
		v.err("workers", "workers must be >= 0")
	}
	if !in(n.Audit.Scope, "all", "relevant") {
		v.err("audit.scope", "audit.scope %q not in {all,relevant}", n.Audit.Scope)
	}
	if n.DefaultSite != "" && cfg.Site(n.DefaultSite) == nil {
		v.err("default_site", "default_site %q is not a configured site", n.DefaultSite)
	}
	// rule 9
	if len(cfg.Sites) > MaxSites {
		v.err("sites", "%d sites exceed the maximum of %d per node", len(cfg.Sites), MaxSites)
	}

	names := map[string]string{}
	ids := map[string]bool{}
	for _, s := range cfg.Sites {
		v.file = s.File
		// rule 2: site identity
		if !reSiteID.MatchString(s.SiteID) {
			v.err("site_id", "site_id %q must match %s", s.SiteID, reSiteID)
		}
		if ids[s.SiteID] {
			v.err("site_id", "duplicate site_id %q", s.SiteID)
		}
		ids[s.SiteID] = true
		if len(s.ServerNames) == 0 {
			v.err("server_names", "server_names must not be empty")
		}
		for i, sn := range s.ServerNames {
			p := fmt.Sprintf("server_names[%d]", i)
			if !reServerName.MatchString(sn) {
				v.err(p, "server name %q must match %s", sn, reServerName)
			}
			if other, dup := names[sn]; dup {
				v.err(p, "server name %q already used by site %s", sn, other)
			}
			names[sn] = s.SiteID
		}
		if !in(s.App, "odoo", "generic") {
			v.err("app", "app %q not in {odoo,generic}", s.App)
		}
		if len(s.Upstream.Servers) == 0 {
			v.err("upstream.servers", "upstream.servers must not be empty")
		}
		hp := func(p, a string) {
			h, port, err := net.SplitHostPort(a)
			n, perr := strconv.Atoi(port)
			if err != nil || h == "" || perr != nil || n < 1 || n > 65535 {
				v.err(p, "%q is not host:port", a)
			}
		}
		for i, a := range s.Upstream.Servers {
			hp(fmt.Sprintf("upstream.servers[%d]", i), a)
		}
		if rt := s.Upstream.Realtime; rt != nil {
			if len(rt.Path) == 0 || rt.Path[0] != '/' {
				v.err("upstream.realtime.path", "path %q must start with /", rt.Path)
			}
			if len(rt.Servers) == 0 {
				v.err("upstream.realtime.servers", "must not be empty")
			}
			for i, a := range rt.Servers {
				hp(fmt.Sprintf("upstream.realtime.servers[%d]", i), a)
			}
		}
		if !in(s.TLS.Mode, "off", "on", "redirect") {
			v.err("tls.mode", "tls.mode %q not in {off,on,redirect}", s.TLS.Mode)
		} else if s.TLS.Mode != "off" {
			cert, key := CertPaths(s)
			if _, err := os.Stat(env.DataDir()); err != nil {
				v.warn("tls", "WAF_DATA_DIR %s missing; cannot check %s", env.DataDir(), cert)
			} else {
				for _, f := range []string{cert, key} {
					if _, err := os.Stat(f); err != nil {
						v.err("tls", "certificate file %s not found", f)
					}
				}
			}
		}
		e, err := Effective(cfg, s.SiteID, cat, false)
		if err != nil {
			v.err("profile", "%v", err)
			continue
		}
		validateWAF(v, cfg, cat, &e.WAF)
	}
	return v.issues
}

// CertPaths returns the cert and key file of a TLS site.
func CertPaths(s *Site) (string, string) {
	dir := filepath.Join(env.DataDir(), "certs", s.SiteID)
	cert, key := s.TLS.Cert, s.TLS.Key
	if cert == "" {
		cert = "fullchain.pem"
	}
	if key == "" {
		key = "privkey.pem"
	}
	if !filepath.IsAbs(cert) {
		cert = filepath.Join(dir, cert)
	}
	if !filepath.IsAbs(key) {
		key = filepath.Join(dir, key)
	}
	return cert, key
}

func validateWAF(v *vctx, cfg *Config, cat *catalog.Catalog, w *WAF) {
	// rule 3
	if !in(w.Mode, "enforce", "count") {
		v.err("mode", "mode %q not in {enforce,count}", w.Mode)
	}
	if !in(w.DefaultAction, "allow", "block") {
		v.err("default_action", "default_action %q not in {allow,block}", w.DefaultAction)
	}
	if !in(w.Fail.PCRELimit, "closed", "block", "open") {
		v.err("fail.pcre_limit", "fail.pcre_limit %q not in {closed,block,open}", w.Fail.PCRELimit)
	}
	if !in(w.Fail.BodyError, "closed", "block", "open") {
		v.err("fail.body_error", "fail.body_error %q not in {closed,block,open}", w.Fail.BodyError)
	}
	if w.BodyLimit < 1 || w.BodyLimit > 1048576 {
		v.err("body_limit", "body_limit %d out of range 1-1048576", w.BodyLimit)
	}
	// rule 4
	if !in(w.ClientIP.Source, "remote_addr", "xff") {
		v.err("client_ip.source", "client_ip.source %q not in {remote_addr,xff}", w.ClientIP.Source)
	}
	if w.ClientIP.Source == "xff" && len(w.ClientIP.TrustedProxies) == 0 {
		v.err("client_ip.trusted_proxies", "client_ip.source xff requires trusted_proxies")
	}
	for i, c := range w.ClientIP.TrustedProxies {
		p := fmt.Sprintf("client_ip.trusted_proxies[%d]", i)
		pf, err := netip.ParsePrefix(c)
		if err != nil {
			v.err(p, "invalid CIDR %q", c)
			continue
		}
		if pf.Bits() == 0 && !cfg.Node.Lab.Enabled {
			v.err(p, "%s trusts every address; allowed only with node lab.enabled", c)
		}
	}
	// rule 5
	enabled := map[string]bool{}
	for i, g := range w.RuleGroups {
		p := fmt.Sprintf("rule_groups[%d]", i)
		cg := cat.GroupByName(g.Name)
		if cg == nil {
			v.err(p+".name", "unknown rule group %q", g.Name)
			continue
		}
		if g.Enabled != nil && *g.Enabled {
			enabled[g.Name] = true
		} else if cg.Optional {
			v.warn(p+".enabled", "optional group %s is listed without enabled: true; it stays disabled", g.Name)
		}
		if !in(g.OverrideAction, "none", "count") {
			v.err(p+".override_action", "override_action %q not in {none,count}", g.OverrideAction)
		}
		for rn, act := range g.RuleActionOverrides {
			if cat.RuleByName(g.Name, rn) == nil {
				v.err(p+".rule_action_overrides."+rn, "rule %q is not in group %s", rn, g.Name)
			}
			if !in(act, "block", "count", "allow") {
				v.err(p+".rule_action_overrides."+rn, "action %q not in {block,count,allow}", act)
			}
		}
		if g.ScopeDown != nil {
			validateMatch(v, cfg, cat, p+".scope_down", g.ScopeDown)
		}
	}
	// rule 6
	if len(w.CustomRules) > 99 {
		v.err("custom_rules", "%d custom rules exceed the maximum of 99", len(w.CustomRules))
	}
	seen := map[string]bool{}
	for i, r := range w.CustomRules {
		p := fmt.Sprintf("custom_rules[%d]", i)
		if !reCustomName.MatchString(r.Name) {
			v.err(p+".name", "name %q must match %s", r.Name, reCustomName)
		}
		if seen[r.Name] {
			v.err(p+".name", "duplicate custom rule %q", r.Name)
		}
		seen[r.Name] = true
		if r.Slot != "start" && !(len(r.Slot) > 6 && r.Slot[:6] == "after:" && enabled[r.Slot[6:]]) {
			v.err(p+".slot", "slot %q must be start or after:<enabled group name>", r.Slot)
		}
		if !in(r.Action, "block", "allow", "count") {
			v.err(p+".action", "action %q not in {block,allow,count}", r.Action)
		}
		validateMatch(v, cfg, cat, p+".match", &r.Match)
	}
	// rule 7
	if rl := w.RateLimit; rl != nil {
		if rl.Limit < 10 {
			v.err("rate_limit.limit", "limit %d must be >= 10", rl.Limit)
		}
		if rl.WindowSec != 60 && rl.WindowSec != 120 && rl.WindowSec != 300 && rl.WindowSec != 600 {
			v.err("rate_limit.window_sec", "window_sec %d not in {60,120,300,600}", rl.WindowSec)
		}
		if !in(rl.Action, "block", "count") {
			v.err("rate_limit.action", "action %q not in {block,count}", rl.Action)
		}
	}
	if gb := w.GeoBlock; gb != nil {
		validateGeo(v, cfg, "geo_block.countries", gb.Countries)
		if !in(gb.Action, "block", "count") {
			v.err("geo_block.action", "action %q not in {block,count}", gb.Action)
		}
	}
	// rule 8
	for i, po := range w.PathOverrides {
		p := fmt.Sprintf("path_overrides[%d]", i)
		if len(po.PathPrefix) == 0 || po.PathPrefix[0] != '/' {
			v.err(p+".path_prefix", "path_prefix %q must start with /", po.PathPrefix)
		}
		for rn, act := range po.Rules {
			found := false
			for _, r := range cat.Rules() {
				if r.Name == rn {
					found = true
				}
			}
			if !found {
				v.err(p+".rules."+rn, "unknown rule %q", rn)
			}
			if !in(act, "block", "count", "allow") {
				v.err(p+".rules."+rn, "action %q not in {block,count,allow}", act)
			}
		}
	}
}

func validateGeo(v *vctx, cfg *Config, p string, codes []string) {
	if len(codes) == 0 {
		v.err(p, "country list must not be empty")
	}
	for _, c := range codes {
		if !reGeo.MatchString(c) {
			v.err(p, "country code %q must match %s", c, reGeo)
		}
	}
	if !cfg.Node.GeoIP.Enabled {
		v.err(p, "geo conditions require node geoip.enabled: true")
	}
}

func validateStr(v *vctx, p string, m *StrMatch, needName bool) {
	if needName && m.Name == "" {
		v.err(p+".name", "name is required")
	}
	if !needName && m.Name != "" {
		v.err(p+".name", "name is not allowed for uri_path")
	}
	for _, s := range []string{m.Exact, m.StartsWith, m.Contains} {
		if strings.ContainsAny(s, "'\"\r\n") {
			v.err(p, "value %q must not contain quotes or newlines", s)
		}
	}
	if strings.ContainsAny(m.Regex+m.Name, "\r\n") || strings.ContainsAny(m.Name, "'\" ") {
		v.err(p, "name/regex must not contain newlines (name: no quotes or spaces)")
	}
	n := 0
	for _, s := range []string{m.Exact, m.StartsWith, m.Contains, m.Regex} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		v.err(p, "exactly one of exact|starts_with|contains|regex is required (found %d)", n)
	}
	if m.Regex != "" {
		if _, err := regexp.Compile(m.Regex); err != nil {
			v.warn(p+".regex", "regex %q is not valid RE2 (PCRE may still accept it): %v", m.Regex, err)
		}
	}
	for _, t := range m.Transform {
		if !in(t, "urlDecodeUni", "lowercase") {
			v.err(p+".transform", "transform %q not in {urlDecodeUni,lowercase}", t)
		}
	}
}

func validateMatch(v *vctx, cfg *Config, cat *catalog.Catalog, p string, m *Match) {
	if len(m.All) == 0 {
		v.err(p+".all", "match.all must not be empty")
	}
	if len(m.All) > 6 {
		v.err(p+".all", "%d conditions exceed the maximum of 6", len(m.All))
	}
	for i, c := range m.All {
		cp := fmt.Sprintf("%s.all[%d]", p, i)
		k := c.Kinds()
		if len(k) != 1 {
			v.err(cp, "exactly one condition kind is required (found %v)", k)
			continue
		}
		switch k[0] {
		case "label":
			if cat.RuleByLabel(c.Label) == nil {
				v.err(cp+".label", "unknown label %q", c.Label)
			}
		case "label_namespace":
			ok := false
			for _, g := range cat.Groups {
				if g.LabelNS == c.LabelNamespace {
					ok = true
				}
			}
			if !ok {
				v.err(cp+".label_namespace", "unknown label namespace %q", c.LabelNamespace)
			}
		case "uri_path":
			validateStr(v, cp+".uri_path", c.URIPath, false)
		case "header":
			validateStr(v, cp+".header", c.Header, true)
		case "query_arg":
			validateStr(v, cp+".query_arg", c.QueryArg, true)
		case "method":
			if len(c.Method) == 0 {
				v.err(cp+".method", "method list must not be empty")
			}
			for _, m := range c.Method {
				if !reMethod.MatchString(m) {
					v.err(cp+".method", "method %q must be uppercase", m)
				}
			}
		case "ip_set":
			if len(c.IPSet) == 0 {
				v.err(cp+".ip_set", "ip_set must not be empty")
			}
			for _, s := range c.IPSet {
				if _, err := netip.ParsePrefix(s); err != nil {
					if _, err2 := netip.ParseAddr(s); err2 != nil {
						v.err(cp+".ip_set", "invalid CIDR %q", s)
					}
				}
			}
		case "geo":
			validateGeo(v, cfg, cp+".geo", c.Geo)
		case "size":
			if !reSizeComp.MatchString(c.Size.Component) {
				v.err(cp+".size.component", "component %q must match %s", c.Size.Component, reSizeComp)
			}
			if !in(c.Size.Op, "gt", "ge", "lt", "le", "eq") {
				v.err(cp+".size.op", "op %q not in {gt,ge,lt,le,eq}", c.Size.Op)
			}
			if c.Size.Value < 0 {
				v.err(cp+".size.value", "value must be >= 0")
			}
		}
	}
}
