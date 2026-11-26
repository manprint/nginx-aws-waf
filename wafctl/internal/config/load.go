package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"nginxawswaf/wafctl/internal/env"
)

// decodeFile strictly decodes one YAML document; errors carry the file path.
func decodeFile(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s: empty file", path)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Load reads node.yaml, sites/*.yaml and profiles (dir/profiles first, then $WAF_HOME/profiles).
func Load(dir string) (*Config, error) {
	cfg := &Config{Dir: dir, Profiles: map[string]*Profile{}}
	n := &Node{}
	np := filepath.Join(dir, "node.yaml")
	if err := decodeFile(np, n); err != nil {
		return nil, err
	}
	n.File = np
	n.applyDefaults()
	cfg.Node = n

	files, err := filepath.Glob(filepath.Join(dir, "sites", "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, p := range files {
		s := &Site{}
		if err := decodeFile(p, s); err != nil {
			return nil, err
		}
		s.File = p
		if want := strings.TrimSuffix(filepath.Base(p), ".yaml"); s.SiteID != want {
			return nil, fmt.Errorf("%s: site_id %q must equal the file name %q", p, s.SiteID, want)
		}
		cfg.Sites = append(cfg.Sites, s)
	}

	pdirs := []string{filepath.Join(dir, "profiles")}
	if h, err := env.Home(); err == nil {
		pdirs = append(pdirs, filepath.Join(h, "profiles"))
	}
	for _, pd := range pdirs {
		pf, _ := filepath.Glob(filepath.Join(pd, "*.yaml"))
		sort.Strings(pf)
		for _, p := range pf {
			name := strings.TrimSuffix(filepath.Base(p), ".yaml")
			if _, seen := cfg.Profiles[name]; seen {
				continue // the config dir wins over $WAF_HOME
			}
			pr := &Profile{}
			if err := decodeFile(p, pr); err != nil {
				return nil, err
			}
			pr.File = p
			if pr.Name == "" {
				pr.Name = name
			}
			if pr.Name != name {
				return nil, fmt.Errorf("%s: name %q must equal the file name %q", p, pr.Name, name)
			}
			cfg.Profiles[name] = pr
		}
	}
	return cfg, nil
}

// Site returns the site with id, or nil.
func (c *Config) Site(id string) *Site {
	for _, s := range c.Sites {
		if s.SiteID == id {
			return s
		}
	}
	return nil
}

// SiteIndex returns the index of id in the sorted site_id list (D23), or -1.
func (c *Config) SiteIndex(id string) int {
	ids := make([]string, 0, len(c.Sites))
	for _, s := range c.Sites {
		ids = append(ids, s.SiteID)
	}
	sort.Strings(ids)
	for i, x := range ids {
		if x == id {
			return i
		}
	}
	return -1
}

func (n *Node) applyDefaults() {
	if n.Role == "" {
		n.Role = "node"
	}
	if n.Network == "" {
		n.Network = "host"
	}
	if n.Listen.HTTP == 0 {
		n.Listen.HTTP = map[bool]int{true: 80, false: 8080}[n.Network == "host"]
	}
	if n.Listen.HTTPS == 0 {
		n.Listen.HTTPS = map[bool]int{true: 443, false: 8443}[n.Network == "host"]
	}
	if n.Listen.IPv6 == nil {
		t := true
		n.Listen.IPv6 = &t
	}
	if n.Audit.Scope == "" {
		n.Audit.Scope = "all"
	}
	if n.Central.IngestPort == 0 {
		n.Central.IngestPort = 6000
	}
	if n.Central.PKIPort == 0 {
		n.Central.PKIPort = 6001
	}
	if n.Retention.RawDays == 0 {
		n.Retention.RawDays = 7
	}
	if n.Retention.LogHours == 0 {
		n.Retention.LogHours = 24
	}
}
