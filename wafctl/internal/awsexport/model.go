// Package awsexport converts a site's effective WAF settings into an AWS WAFv2 web ACL:
// the CreateWebACL input (+ CreateIPSet inputs) as JSON, or Terraform (hcl.go).
package awsexport

import (
	"fmt"
	"regexp"
	"strings"

	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/config"
)

// Options of the export.
type Options struct {
	AllowLossy bool
	Region     string // default eu-central-1
	Account    string // default 000000000000
}

// Document is the JSON export.
type Document struct {
	WebACL      M        `json:"web_acl"`
	IPSets      []M      `json:"ip_sets"`
	ManualSteps []string `json:"manual_steps"`
	Lossy       []string `json:"lossy"`
}

// LossyError lists why a site cannot be exported faithfully (use --allow-lossy).
type LossyError struct {
	Site    string
	Reasons []string
}

func (e *LossyError) Error() string {
	return fmt.Sprintf("site %s is not aws-compatible: %s (use --allow-lossy to export without these features)", e.Site, strings.Join(e.Reasons, "; "))
}

// Reasons returns the lossy reasons of e: config.Compat plus the export-only ones.
func Reasons(e *config.EffectiveSite, cat *catalog.Catalog) []string {
	r := config.Compat(e, cat)
	if e.WAF.Mode == "count" && e.WAF.DefaultAction == "block" {
		r = append(r, "shadow mode with default_action block")
	}
	return r
}

type builder struct {
	e      *config.EffectiveSite
	cat    *catalog.Catalog
	opt    Options
	doc    *Document
	ipSets map[string]bool
}

const (
	stepAssociate = "Associate the web ACL with the ALB (aws_wafv2_web_acl_association or console)"
	stepIPSetARNs = "Replace the IP set ARNs in web_acl with the ARNs returned by CreateIPSet (create the IP sets first)"
)

// Build exports e. Without AllowLossy, lossy reasons → *LossyError.
func Build(e *config.EffectiveSite, cat *catalog.Catalog, opt Options) (*Document, error) {
	if opt.Region == "" {
		opt.Region = "eu-central-1"
	}
	if opt.Account == "" {
		opt.Account = "000000000000"
	}
	reasons := Reasons(e, cat)
	if len(reasons) > 0 && !opt.AllowLossy {
		return nil, &LossyError{Site: e.Site.SiteID, Reasons: reasons}
	}
	b := &builder{e: e, cat: cat, opt: opt, ipSets: map[string]bool{},
		doc: &Document{IPSets: []M{}, ManualSteps: []string{}, Lossy: append([]string{}, reasons...)}}
	rules, err := b.rules()
	if err != nil {
		return nil, err
	}
	w := &e.WAF
	site := e.Site.SiteID
	b.doc.WebACL = M{
		"Name":             "waf-" + site,
		"Scope":            "REGIONAL",
		"DefaultAction":    action(w.DefaultAction),
		"VisibilityConfig": visibility("waf-" + site),
		"Rules":            rules,
	}
	if w.BodyLimit != 8192 && inAWSBodyLimits(w.BodyLimit) {
		b.doc.ManualSteps = append(b.doc.ManualSteps, fmt.Sprintf("Set the ALB WAF body inspection limit to %d KB (Load balancer attributes / WAF integration)", w.BodyLimit/1024))
	}
	if len(b.doc.IPSets) > 0 {
		b.doc.ManualSteps = append(b.doc.ManualSteps, stepIPSetARNs)
	}
	b.doc.ManualSteps = append(b.doc.ManualSteps, stepAssociate)
	return b.doc, nil
}

func inAWSBodyLimits(n int) bool {
	for _, b := range config.AWSBodyLimits {
		if b == n {
			return true
		}
	}
	return false
}

// rules: rate rule, start custom rules (GeoBlock first), then each enabled managed group
// followed by its after:<group> custom rules; priorities 0, 10, 20, …
func (b *builder) rules() ([]M, error) {
	w := &b.e.WAF
	var out []M
	add := func(r M) {
		r["Priority"] = len(out) * 10
		out = append(out, r)
	}
	if rl := w.RateLimit; rl != nil {
		add(M{"Name": "RateLimit", "Action": b.ruleAction(rl.Action), "VisibilityConfig": visibility("RateLimit"),
			"Statement": M{"RateBasedStatement": M{"Limit": rl.Limit, "EvaluationWindowSec": rl.WindowSec, "AggregateKeyType": "IP"}}})
	}
	customs := customRuleList(w)
	addCustom := func(slot string) error {
		for _, cr := range customs {
			if cr.Slot != slot {
				continue
			}
			st, err := stmtCtx{b: b, rule: cr.Name}.match(&cr.Match)
			if err != nil {
				return err
			}
			add(M{"Name": cr.Name, "Action": b.ruleAction(cr.Action), "VisibilityConfig": visibility(cr.Name), "Statement": st})
		}
		return nil
	}
	if err := addCustom("start"); err != nil {
		return nil, err
	}
	for i := range w.RuleGroups {
		g := &w.RuleGroups[i]
		cg := b.cat.GroupByName(g.Name)
		if g.Enabled == nil || !*g.Enabled || cg == nil {
			continue
		}
		r, err := b.managed(g, cg)
		if err != nil {
			return nil, err
		}
		add(r)
		if err := addCustom("after:" + g.Name); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (b *builder) managed(g *config.RuleGroup, cg *catalog.Group) (M, error) {
	name := "AWS-" + g.Name
	over := M{"None": M{}}
	if b.e.WAF.Mode == "count" || g.OverrideAction == "count" {
		over = M{"Count": M{}}
	}
	mrg := M{"VendorName": cg.Vendor, "Name": cg.Name}
	var rao []M
	for _, r := range cg.Rules { // catalog order
		act, ok := g.RuleActionOverrides[r.Name]
		if ok && act != r.DefaultAction {
			rao = append(rao, M{"Name": r.Name, "ActionToUse": action(act)})
		}
	}
	if len(rao) > 0 {
		mrg["RuleActionOverrides"] = rao
	}
	if g.ScopeDown != nil {
		st, err := stmtCtx{b: b, rule: name}.match(g.ScopeDown)
		if err != nil {
			return nil, err
		}
		mrg["ScopeDownStatement"] = st
	}
	return M{"Name": name, "OverrideAction": over, "VisibilityConfig": visibility(name),
		"Statement": M{"ManagedRuleGroupStatement": mrg}}, nil
}

// customRuleList: GeoBlock (slot start) first, then the custom rules (same as the render).
func customRuleList(w *config.WAF) []config.CustomRule {
	var out []config.CustomRule
	if gb := w.GeoBlock; gb != nil {
		out = append(out, config.CustomRule{Name: "GeoBlock", Slot: "start", Action: gb.Action,
			Match: config.Match{All: []config.Cond{{Geo: gb.Countries}}}})
	}
	return append(out, w.CustomRules...)
}

func (b *builder) ruleAction(a string) M {
	if b.e.WAF.Mode == "count" {
		return M{"Count": M{}}
	}
	return action(a)
}

func action(a string) M {
	switch a {
	case "block":
		return M{"Block": M{}}
	case "count":
		return M{"Count": M{}}
	}
	return M{"Allow": M{}}
}

var reMetric = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func visibility(name string) M {
	m := reMetric.ReplaceAllString(name, "_")
	if len(m) > 128 {
		m = m[:128]
	}
	return M{"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": m}
}

func (b *builder) ipSetName(rule, suffix string) string {
	base := reMetric.ReplaceAllString(fmt.Sprintf("waf-%s-%s", b.e.Site.SiteID, rule), "_")
	n := base + "-" + suffix
	for i := 2; b.ipSets[n]; i++ {
		n = fmt.Sprintf("%s-%d-%s", base, i, suffix)
	}
	b.ipSets[n] = true
	return n
}

func (b *builder) ipSetARN(name string) string {
	return fmt.Sprintf("arn:aws:wafv2:%s:%s:regional/ipset/%s/00000000-0000-0000-0000-000000000000", b.opt.Region, b.opt.Account, name)
}
