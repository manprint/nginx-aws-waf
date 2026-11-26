package config

import (
	"fmt"
	"sort"
	"strings"

	"nginxawswaf/wafctl/internal/catalog"
)

// DefaultProfile is used when a site sets no profile.
const DefaultProfile = "aws-default"

// EffectiveSite is a site with its fully merged WAF settings.
type EffectiveSite struct {
	Site         *Site
	Node         *Node
	WAF          WAF               // merged; every RuleGroup.Enabled is non-nil
	ProfileChain []string          // root first
	Origins      map[string]string // setting key → default|profile:<name>|site|bypass
	Bypass       bool
}

// Defaults returns the built-in lowest merge layer.
func Defaults(cat *catalog.Catalog) WAF {
	w := WAF{
		Mode:          "enforce",
		DefaultAction: "allow",
		BodyLimit:     8192,
		ClientIP:      ClientIP{Source: "remote_addr", TrustedProxies: []string{}},
		Fail:          Fail{PCRELimit: "closed", BodyError: "open"},
		BlockPage:     "aws",
	}
	for _, g := range cat.Groups {
		if !g.Optional {
			t := true
			w.RuleGroups = append(w.RuleGroups, RuleGroup{Name: g.Name, Enabled: &t, OverrideAction: "none"})
		}
	}
	return w
}

// profileChain resolves extends, root first.
func profileChain(cfg *Config, name string) ([]*Profile, error) {
	var chain []*Profile
	seen := map[string]bool{}
	path := []string{}
	for name != "" {
		path = append(path, name)
		if seen[name] {
			return nil, fmt.Errorf("profile cycle %s", strings.Join(path, "->"))
		}
		seen[name] = true
		p, ok := cfg.Profiles[name]
		if !ok {
			return nil, fmt.Errorf("profile %q not found", name)
		}
		chain = append([]*Profile{p}, chain...)
		name = p.Extends
	}
	return chain, nil
}

// Effective merges defaults ← profile chain ← site ← bypass for one site.
func Effective(cfg *Config, siteID string, cat *catalog.Catalog, bypass bool) (*EffectiveSite, error) {
	s := cfg.Site(siteID)
	if s == nil {
		return nil, fmt.Errorf("site %q not found", siteID)
	}
	pname := s.Profile
	if pname == "" {
		pname = DefaultProfile
	}
	chain, err := profileChain(cfg, pname)
	if err != nil {
		return nil, fmt.Errorf("site %s: %w", siteID, err)
	}
	e := &EffectiveSite{Site: s, Node: cfg.Node, Origins: map[string]string{}, Bypass: bypass}
	w := Defaults(cat)
	for _, k := range []string{"mode", "default_action", "body_limit", "client_ip.source", "client_ip.trusted_proxies", "fail.pcre_limit", "fail.body_error", "block_page"} {
		e.Origins[k] = "default"
	}
	for _, g := range w.RuleGroups {
		e.Origins["group:"+g.Name+".enabled"] = "default"
	}
	for _, p := range chain {
		e.ProfileChain = append(e.ProfileChain, p.Name)
		if err := mergeWAF(&w, &p.WAF, "profile:"+p.Name, e.Origins); err != nil {
			return nil, fmt.Errorf("%s: %w", p.File, err)
		}
	}
	if err := mergeWAF(&w, &s.WAF, "site", e.Origins); err != nil {
		return nil, fmt.Errorf("%s: %w", s.File, err)
	}
	if bypass {
		w.Mode = "count"
		e.Origins["mode"] = "bypass"
	}
	// resolve Enabled and order groups by catalog order (unknown names last, validated in Validate).
	idx := map[string]int{}
	for i, g := range cat.Groups {
		idx[g.Name] = i
	}
	for i := range w.RuleGroups {
		g := &w.RuleGroups[i]
		if g.Enabled == nil {
			on := false
			if cg := cat.GroupByName(g.Name); cg != nil {
				on = !cg.Optional
			}
			g.Enabled = &on
		}
		if g.OverrideAction == "" {
			g.OverrideAction = "none"
		}
	}
	sort.SliceStable(w.RuleGroups, func(a, b int) bool {
		ia, oka := idx[w.RuleGroups[a].Name]
		ib, okb := idx[w.RuleGroups[b].Name]
		if !oka {
			ia = len(cat.Groups)
		}
		if !okb {
			ib = len(cat.Groups)
		}
		return ia < ib
	})
	e.WAF = w
	return e, nil
}

func mergeWAF(dst, src *WAF, origin string, o map[string]string) error {
	setS := func(d *string, v, key string) {
		if v != "" {
			*d = v
			o[key] = origin
		}
	}
	setS(&dst.Mode, src.Mode, "mode")
	setS(&dst.DefaultAction, src.DefaultAction, "default_action")
	if src.BodyLimit != 0 {
		dst.BodyLimit = src.BodyLimit
		o["body_limit"] = origin
	}
	setS(&dst.ClientIP.Source, src.ClientIP.Source, "client_ip.source")
	if src.ClientIP.TrustedProxies != nil {
		dst.ClientIP.TrustedProxies = append([]string{}, src.ClientIP.TrustedProxies...)
		o["client_ip.trusted_proxies"] = origin
	}
	setS(&dst.Fail.PCRELimit, src.Fail.PCRELimit, "fail.pcre_limit")
	setS(&dst.Fail.BodyError, src.Fail.BodyError, "fail.body_error")
	setS(&dst.BlockPage, src.BlockPage, "block_page")

	for _, sg := range src.RuleGroups {
		var d *RuleGroup
		for i := range dst.RuleGroups {
			if dst.RuleGroups[i].Name == sg.Name {
				d = &dst.RuleGroups[i]
				break
			}
		}
		if d == nil {
			dst.RuleGroups = append(dst.RuleGroups, RuleGroup{Name: sg.Name})
			d = &dst.RuleGroups[len(dst.RuleGroups)-1]
		}
		pre := "group:" + sg.Name
		if sg.Enabled != nil {
			v := *sg.Enabled
			d.Enabled = &v
			o[pre+".enabled"] = origin
		}
		if sg.OverrideAction != "" {
			d.OverrideAction = sg.OverrideAction
			o[pre+".override_action"] = origin
		}
		if len(sg.RuleActionOverrides) > 0 {
			if d.RuleActionOverrides == nil {
				d.RuleActionOverrides = map[string]string{}
			}
			for k, v := range sg.RuleActionOverrides {
				d.RuleActionOverrides[k] = v
				o["rule:"+sg.Name+"/"+k] = origin
			}
		}
		if sg.ScopeDown != nil {
			sd := *sg.ScopeDown
			d.ScopeDown = &sd
			o[pre+".scope_down"] = origin
		}
	}

	for _, cr := range src.CustomRules {
		replaced := false
		for i := range dst.CustomRules {
			if dst.CustomRules[i].Name == cr.Name {
				dst.CustomRules[i] = cr
				replaced = true
				break
			}
		}
		if !replaced {
			dst.CustomRules = append(dst.CustomRules, cr)
		}
		o["custom:"+cr.Name] = origin
	}
	for _, name := range src.DisableCustomRules {
		found := false
		for i := range dst.CustomRules {
			if dst.CustomRules[i].Name == name {
				dst.CustomRules = append(dst.CustomRules[:i], dst.CustomRules[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("disable_custom_rules: unknown custom rule %q", name)
		}
		o["custom:"+name] = origin + " (disabled)"
	}
	dst.PathOverrides = append(dst.PathOverrides, src.PathOverrides...)
	for _, po := range src.PathOverrides {
		o["path_override:"+po.PathPrefix] = origin
	}
	if src.RateLimit != nil {
		rl := *src.RateLimit
		dst.RateLimit = &rl
		o["rate_limit"] = origin
	}
	if src.GeoBlock != nil {
		gb := *src.GeoBlock
		dst.GeoBlock = &gb
		o["geo_block"] = origin
	}
	return nil
}
