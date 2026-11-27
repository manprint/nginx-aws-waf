package render

import (
	"fmt"
	"sort"
	"strings"

	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/config"
)

// customRuleList returns the effective custom rules (GeoBlock first when configured).
func customRuleList(w *config.WAF) []config.CustomRule {
	var out []config.CustomRule
	if gb := w.GeoBlock; gb != nil {
		out = append(out, config.CustomRule{Name: "GeoBlock", Slot: "start", Action: gb.Action,
			Match: config.Match{All: []config.Cond{{Geo: gb.Countries}}}})
	}
	return append(out, w.CustomRules...)
}

// CustomRuleID is the D23 id of custom rule ruleIdx of site siteIdx.
func CustomRuleID(siteIdx, ruleIdx int) int { return 1500000 + siteIdx*1000 + ruleIdx*10 }

// ScopeDownID is the D23 id of the scope-down block of group gi of site siteIdx.
func ScopeDownID(siteIdx, gi int) int { return 1600000 + siteIdx*1000 + gi*10 }

func (r *renderer) customRules(slot string) ([]string, error) {
	var out []string
	for _, s := range r.sites {
		id := s.Eff.Site.SiteID
		for ri, cr := range customRuleList(&s.Eff.WAF) {
			if cr.Slot != slot {
				continue
			}
			N := CustomRuleID(s.Idx, ri)
			prefix := fmt.Sprintf("c%d", N)
			h, err := helpers(id, N, prefix, cr.Match.All, r.cat)
			if err != nil {
				return nil, fmt.Errorf("site %s custom rule %s: %w", id, cr.Name, err)
			}
			out = append(out, h...)
			out = append(out,
				fmt.Sprintf(`SecRule TX:site "@streq %s" "id:%d,phase:2,pass,nolog,auditlog,msg:'AWSWAF %d',tag:'awswaf-rule:custom:%s/%s',logdata:'a=%s;tb=%%{tx.term};ab=%%{tx.awsterm};sc=1;v=;x=',chain"`,
					id, N, N, id, cr.Name, cr.Action),
				`SecRule TX:term "@eq 0" "t:none,chain"`)
			out = append(out, condChain(prefix, cr.Match.All, fmt.Sprintf("setvar:tx.hit_%d=1", N))...)
			if cr.Action != "count" {
				out = append(out,
					fmt.Sprintf(`SecRule TX:hit_%d "@eq 1" "id:%d,phase:2,pass,nolog,chain"`, N, N+8),
					fmt.Sprintf(`SecRule TX:term "@eq 0" "t:none,setvar:tx.term=%d,setvar:tx.term_action=%s"`, N, cr.Action))
			}
		}
	}
	return out, nil
}

func (r *renderer) scopeDowns(gi int) ([]string, error) {
	g := r.cat.Groups[gi]
	var out []string
	for _, s := range r.sites {
		id := s.Eff.Site.SiteID
		for _, rg := range s.Eff.WAF.RuleGroups {
			if rg.Name != g.Name || rg.ScopeDown == nil {
				continue
			}
			SD := ScopeDownID(s.Idx, gi)
			prefix := fmt.Sprintf("sd%d", SD)
			h, err := helpers(id, SD, prefix, rg.ScopeDown.All, r.cat)
			if err != nil {
				return nil, fmt.Errorf("site %s scope-down %s: %w", id, g.Name, err)
			}
			out = append(out, h...)
			out = append(out,
				fmt.Sprintf(`SecRule TX:site "@streq %s" "id:%d,phase:2,pass,nolog,setvar:tx.inscope_%s=0"`, id, SD, g.Key),
				fmt.Sprintf(`SecRule TX:site "@streq %s" "id:%d,phase:2,pass,nolog,chain"`, id, SD+7))
			out = append(out, condChain(prefix, rg.ScopeDown.All, "setvar:tx.inscope_"+g.Key+"=1")...)
		}
	}
	return out, nil
}

// effAction applies the group override_action to a rule action.
func effAction(a string, rg *config.RuleGroup) string {
	if rg != nil && rg.OverrideAction == "count" && (a == "block" || a == "allow") {
		return "count"
	}
	return a
}

func findGroup(w *config.WAF, name string) *config.RuleGroup {
	for i := range w.RuleGroups {
		if w.RuleGroups[i].Name == name {
			return &w.RuleGroups[i]
		}
	}
	return nil
}

// siteFile renders <R>/modsec/sites/<site>.conf.
func (r *renderer) siteFile(s site) (string, error) {
	e := s.Eff
	w := &e.WAF
	id := e.Site.SiteID
	base := 1910000 + s.Idx*10
	l := &lines{}
	l.F("# site %s idx %d", id, s.Idx)
	if w.BodyLimit != 8192 {
		l.F("SecRequestBodyLimit %d", w.BodyLimit)
		l.F("SecRequestBodyNoFilesLimit %d", w.BodyLimit)
	}
	l.F(`SecAction "id:%d,phase:1,pass,nolog,setvar:tx.site=%s,setvar:tx.mode=%s,setvar:tx.default_action=%s,setvar:tx.fail_pcre=%s,setvar:tx.fail_body=%s"`,
		base, id, w.Mode, w.DefaultAction, w.Fail.PCRELimit, w.Fail.BodyError)
	var grp, act []string
	for _, g := range r.cat.Groups {
		rg := findGroup(w, g.Name)
		on := 0
		if rg != nil && rg.Enabled != nil && *rg.Enabled {
			on = 1
		}
		grp = append(grp, fmt.Sprintf("setvar:tx.grp_%s=%d", g.Key, on))
		for _, rr := range g.Rules {
			a := rr.DefaultAction
			if rg != nil {
				if o, ok := rg.RuleActionOverrides[rr.Name]; ok {
					a = o
				}
			}
			a = effAction(a, rg)
			if a != rr.DefaultAction {
				act = append(act, fmt.Sprintf("setvar:tx.act_%d=%s", rr.ID, a))
			}
		}
	}
	l.F(`SecAction "id:%d,phase:2,pass,nolog,%s"`, base+1, strings.Join(grp, ","))
	if len(act) > 0 {
		l.F(`SecAction "id:%d,phase:2,pass,nolog,%s"`, base+2, strings.Join(act, ","))
	}
	for j, po := range w.PathOverrides {
		if j >= 100 {
			return "", fmt.Errorf("site %s: more than 100 path overrides", id)
		}
		names := make([]string, 0, len(po.Rules))
		for n := range po.Rules {
			names = append(names, n)
		}
		sort.Strings(names)
		var sv []string
		for _, n := range names {
			rr := ruleByBareName(r.cat, n)
			if rr == nil {
				return "", fmt.Errorf("site %s path override: unknown rule %q", id, n)
			}
			sv = append(sv, fmt.Sprintf("setvar:tx.act_%d=%s", rr.ID, effAction(po.Rules[n], findGroup(w, rr.Group.Name))))
		}
		l.F(`SecRule TX:raw_path "@beginsWith %s" "id:%d,phase:2,pass,nolog,%s"`, q(po.PathPrefix), 1700000+s.Idx*100+j, strings.Join(sv, ","))
	}
	return l.String(), nil
}

func ruleByBareName(cat *catalog.Catalog, name string) *catalog.Rule {
	for _, rr := range cat.Rules() {
		if rr.Name == name {
			return rr
		}
	}
	return nil
}
