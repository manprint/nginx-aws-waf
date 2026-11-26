package render

import (
	"encoding/json"
	"strconv"

	"nginxawswaf/wafctl/internal/catalog"
)

// IndexEntry describes one rule id in rules-index.json.
type IndexEntry struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	Label string `json:"label"`
	Site  string `json:"site"`
}

func (r *renderer) rulesIndex() ([]byte, error) {
	idx := map[string]IndexEntry{}
	for _, rr := range r.cat.Rules() {
		idx[strconv.Itoa(rr.ID)] = IndexEntry{Group: rr.Group.Name, Name: rr.Name, Label: catalog.FullLabel(rr)}
	}
	for _, s := range r.sites {
		id := s.Eff.Site.SiteID
		for ri, cr := range customRuleList(&s.Eff.WAF) {
			idx[strconv.Itoa(CustomRuleID(s.Idx, ri))] = IndexEntry{Group: "custom:" + id, Name: cr.Name, Site: id}
		}
	}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
