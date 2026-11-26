// Package catalog loads and validates waf/catalog/rules.yaml (D3).
package catalog

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Link is one element of a detector chain.
type Link struct {
	Vars string   `yaml:"vars"`
	Op   string   `yaml:"op"`
	T    []string `yaml:"t,omitempty"`
}

// Rule is one managed rule.
type Rule struct {
	ID            int      `yaml:"id"`
	Name          string   `yaml:"name"`
	Label         string   `yaml:"label"`
	DefaultAction string   `yaml:"default_action"`
	Fidelity      string   `yaml:"fidelity"`
	Detectors     [][]Link `yaml:"detectors"`
	Group         *Group   `yaml:"-"`
}

// Group is one managed rule group.
type Group struct {
	Key      string  `yaml:"key"`
	Name     string  `yaml:"name"`
	Vendor   string  `yaml:"vendor"`
	WCU      int     `yaml:"wcu"`
	LabelNS  string  `yaml:"label_ns"`
	Optional bool    `yaml:"optional"`
	Rules    []*Rule `yaml:"rules"`
}

// Catalog is the whole rule catalog.
type Catalog struct {
	Version int      `yaml:"version"`
	Groups  []*Group `yaml:"groups"`
}

// Load reads and validates a catalog file.
func Load(path string) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var c Catalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Catalog) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported catalog version %d", c.Version)
	}
	ids := map[int]bool{}
	names := map[string]bool{}
	labels := map[string]bool{}
	keys := map[string]bool{}
	for _, g := range c.Groups {
		if g.Key == "" || g.Name == "" {
			return fmt.Errorf("group with empty key or name")
		}
		if keys[g.Key] {
			return fmt.Errorf("duplicate group key %q", g.Key)
		}
		keys[g.Key] = true
		if len(g.Rules) == 0 {
			return fmt.Errorf("group %s has no rules", g.Key)
		}
		for _, r := range g.Rules {
			r.Group = g
			switch {
			case ids[r.ID]:
				return fmt.Errorf("duplicate id %d", r.ID)
			case names[g.Name+"/"+r.Name]:
				return fmt.Errorf("duplicate name %s/%s", g.Name, r.Name)
			case labels[g.LabelNS+r.Label]:
				return fmt.Errorf("duplicate label %s%s", g.LabelNS, r.Label)
			case r.ID <= 0 || r.ID%10 != 0:
				return fmt.Errorf("rule %s: id %d is not a positive multiple of 10", r.Name, r.ID)
			case len(r.Detectors) > 7:
				return fmt.Errorf("rule %s: %d detectors (max 7)", r.Name, len(r.Detectors))
			case r.DefaultAction != "block" && r.DefaultAction != "count":
				return fmt.Errorf("rule %s: default_action %q not in {block,count}", r.Name, r.DefaultAction)
			case r.Fidelity != "exact" && r.Fidelity != "approx" && r.Fidelity != "stub":
				return fmt.Errorf("rule %s: fidelity %q not in {exact,approx,stub}", r.Name, r.Fidelity)
			}
			ids[r.ID], names[g.Name+"/"+r.Name], labels[g.LabelNS+r.Label] = true, true, true
			for i, ch := range r.Detectors {
				if len(ch) == 0 {
					return fmt.Errorf("rule %s: detector %d is an empty chain", r.Name, i)
				}
				for j, l := range ch {
					if l.Vars == "" || l.Op == "" {
						return fmt.Errorf("rule %s: detector %d link %d has empty vars or op", r.Name, i, j)
					}
				}
			}
		}
	}
	return nil
}

// GroupByName returns the group with the AWS name, or nil.
func (c *Catalog) GroupByName(name string) *Group {
	for _, g := range c.Groups {
		if g.Name == name {
			return g
		}
	}
	return nil
}

// GroupByKey returns the group with the short key, or nil.
func (c *Catalog) GroupByKey(key string) *Group {
	for _, g := range c.Groups {
		if g.Key == key {
			return g
		}
	}
	return nil
}

// RuleByName returns the rule of a group (AWS group name) by name, or nil.
func (c *Catalog) RuleByName(group, name string) *Rule {
	g := c.GroupByName(group)
	if g == nil {
		return nil
	}
	for _, r := range g.Rules {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// RuleByID returns the rule with base id, or nil.
func (c *Catalog) RuleByID(id int) *Rule {
	for _, g := range c.Groups {
		for _, r := range g.Rules {
			if r.ID == id {
				return r
			}
		}
	}
	return nil
}

// RuleByLabel returns the rule whose full label equals l, or nil.
func (c *Catalog) RuleByLabel(l string) *Rule {
	for _, g := range c.Groups {
		for _, r := range g.Rules {
			if FullLabel(r) == l {
				return r
			}
		}
	}
	return nil
}

// Rules returns all rules in catalog order.
func (c *Catalog) Rules() []*Rule {
	var out []*Rule
	for _, g := range c.Groups {
		out = append(out, g.Rules...)
	}
	return out
}

// FullLabel returns label_ns + label.
func FullLabel(r *Rule) string { return r.Group.LabelNS + r.Label }

// BaseID returns the group base id (e.g. 1200000).
func BaseID(g *Group) int { return g.Rules[0].ID / 10000 * 10000 }
