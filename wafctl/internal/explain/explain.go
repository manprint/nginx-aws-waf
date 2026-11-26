// Package explain prints the effective WAF configuration of a site.
package explain

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/config"
)

// RuleRow is one managed rule of the site.
type RuleRow struct {
	Group     string `json:"group"`
	Rule      string `json:"rule"`
	Default   string `json:"default"`
	Effective string `json:"effective"`
	Origin    string `json:"origin"`
	Fidelity  string `json:"fidelity"`
}

// Report is the explain output.
type Report struct {
	Site        string            `json:"site"`
	Profiles    []string          `json:"profiles"`
	Rules       []RuleRow         `json:"rules"`
	ScopeDowns  map[string]string `json:"scope_downs"`
	CustomRules []string          `json:"custom_rules"`
	PathOver    []string          `json:"path_overrides"`
	Settings    map[string]string `json:"settings"`
	Compat      string            `json:"compat"`
}

// CondString renders a condition in DSL form.
func CondString(c config.Cond) string {
	neg := ""
	if c.Negate {
		neg = "NOT "
	}
	sm := func(kind string, m *config.StrMatch) string {
		op, v := "", ""
		switch {
		case m.Exact != "":
			op, v = "exact", m.Exact
		case m.StartsWith != "":
			op, v = "starts_with", m.StartsWith
		case m.Contains != "":
			op, v = "contains", m.Contains
		default:
			op, v = "regex", m.Regex
		}
		n := ""
		if m.Name != "" {
			n = "[" + m.Name + "]"
		}
		t := ""
		if len(m.Transform) > 0 {
			t = " (" + strings.Join(m.Transform, ",") + ")"
		}
		return fmt.Sprintf("%s%s %s %q%s", kind, n, op, v, t)
	}
	var s string
	switch {
	case c.Label != "":
		s = "label " + c.Label
	case c.LabelNamespace != "":
		s = "label_namespace " + c.LabelNamespace
	case c.URIPath != nil:
		s = sm("uri_path", c.URIPath)
	case c.Header != nil:
		s = sm("header", c.Header)
	case c.QueryArg != nil:
		s = sm("query_arg", c.QueryArg)
	case c.Method != nil:
		s = "method in " + strings.Join(c.Method, ",")
	case c.IPSet != nil:
		s = "ip in " + strings.Join(c.IPSet, ",")
	case c.Geo != nil:
		s = "geo in " + strings.Join(c.Geo, ",")
	case c.Size != nil:
		s = fmt.Sprintf("size(%s) %s %d", c.Size.Component, c.Size.Op, c.Size.Value)
	}
	return neg + s
}

func matchString(m *config.Match) string {
	var p []string
	for _, c := range m.All {
		p = append(p, CondString(c))
	}
	return strings.Join(p, " AND ")
}

// Build computes the report.
func Build(e *config.EffectiveSite, cat *catalog.Catalog) *Report {
	w := &e.WAF
	r := &Report{Site: e.Site.SiteID, Profiles: e.ProfileChain, ScopeDowns: map[string]string{}, Settings: map[string]string{}}
	for _, g := range cat.Groups {
		var rg *config.RuleGroup
		for i := range w.RuleGroups {
			if w.RuleGroups[i].Name == g.Name {
				rg = &w.RuleGroups[i]
			}
		}
		if rg == nil || rg.Enabled == nil || !*rg.Enabled {
			continue
		}
		if rg.ScopeDown != nil {
			r.ScopeDowns[g.Name] = matchString(rg.ScopeDown)
		}
		for _, rr := range g.Rules {
			eff, origin := rr.DefaultAction, "default"
			if o, ok := rg.RuleActionOverrides[rr.Name]; ok {
				eff, origin = o, e.Origins["rule:"+g.Name+"/"+rr.Name]
			}
			if rg.OverrideAction == "count" && (eff == "block" || eff == "allow") {
				eff, origin = "count", e.Origins["group:"+g.Name+".override_action"]
			}
			if e.Bypass || w.Mode == "count" {
				origin += " (mode " + w.Mode + ")"
			}
			r.Rules = append(r.Rules, RuleRow{g.Name, rr.Name, rr.DefaultAction, eff, origin, rr.Fidelity})
		}
	}
	idx := 0
	add := func(cr config.CustomRule) {
		r.CustomRules = append(r.CustomRules, fmt.Sprintf("%d. [%s] %s %s: %s (%s)", idx+1, cr.Slot, cr.Name, cr.Action, matchString(&cr.Match), e.Origins["custom:"+cr.Name]))
		idx++
	}
	all := w.CustomRules
	if gb := w.GeoBlock; gb != nil {
		all = append([]config.CustomRule{{Name: "GeoBlock", Slot: "start", Action: gb.Action, Match: config.Match{All: []config.Cond{{Geo: gb.Countries}}}}}, all...)
	}
	slots := []string{"start"}
	for _, g := range cat.Groups {
		slots = append(slots, "after:"+g.Name)
	}
	for _, s := range slots {
		for _, cr := range all {
			if cr.Slot == s {
				add(cr)
			}
		}
	}
	for _, po := range w.PathOverrides {
		var p []string
		for k, v := range po.Rules {
			p = append(p, k+"="+v)
		}
		r.PathOver = append(r.PathOver, po.PathPrefix+": "+strings.Join(p, ", "))
	}
	set := r.Settings
	set["mode"] = w.Mode + " (" + e.Origins["mode"] + ")"
	set["default_action"] = w.DefaultAction + " (" + e.Origins["default_action"] + ")"
	set["body_limit"] = fmt.Sprintf("%d (%s)", w.BodyLimit, e.Origins["body_limit"])
	set["fail"] = fmt.Sprintf("pcre_limit=%s body_error=%s", w.Fail.PCRELimit, w.Fail.BodyError)
	set["client_ip"] = w.ClientIP.Source
	if len(w.ClientIP.TrustedProxies) > 0 {
		set["client_ip"] += " trusted=" + strings.Join(w.ClientIP.TrustedProxies, ",")
	}
	set["rate_limit"] = "none"
	if rl := w.RateLimit; rl != nil {
		set["rate_limit"] = fmt.Sprintf("%d/%ds %s", rl.Limit, rl.WindowSec, rl.Action)
	}
	if reasons := config.Compat(e, cat); len(reasons) > 0 {
		r.Compat = "nginx-only (" + strings.Join(reasons, "; ") + ")"
	} else {
		r.Compat = "aws-compatible"
	}
	return r
}

// Write prints the report as table or json.
func Write(w io.Writer, r *Report, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	fmt.Fprintf(w, "site %s  profiles %s\n\n", r.Site, strings.Join(r.Profiles, " -> "))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GROUP\tRULE\tDEFAULT\tEFFECTIVE\tORIGIN\tFIDELITY")
	for _, x := range r.Rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", x.Group, x.Rule, x.Default, x.Effective, x.Origin, x.Fidelity)
	}
	tw.Flush()
	fmt.Fprintln(w, "\nscope-down:")
	if len(r.ScopeDowns) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for g, s := range r.ScopeDowns {
		fmt.Fprintf(w, "  %s: %s\n", g, s)
	}
	fmt.Fprintln(w, "\ncustom rules (evaluation order):")
	if len(r.CustomRules) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, c := range r.CustomRules {
		fmt.Fprintln(w, "  "+c)
	}
	if len(r.PathOver) > 0 {
		fmt.Fprintln(w, "\npath overrides (nginx-only):")
		for _, p := range r.PathOver {
			fmt.Fprintln(w, "  "+p)
		}
	}
	fmt.Fprintln(w, "\nsettings:")
	for _, k := range []string{"mode", "default_action", "body_limit", "fail", "client_ip", "rate_limit"} {
		fmt.Fprintf(w, "  %-15s %s\n", k, r.Settings[k])
	}
	fmt.Fprintf(w, "\ncompat: %s\n", r.Compat)
	return nil
}
