package render

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"nginxawswaf/wafctl/internal/catalog"
)

// staticAndData adds <R>/data/*.data and <R>/static/<site>/{403,500}.html from WAF_HOME (and the config pages dir).
func (r *renderer) staticAndData(files map[string][]byte) error {
	data, err := filepath.Glob(filepath.Join(r.opt.Home, "waf", "data", "*.data"))
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("no data files in %s/waf/data", r.opt.Home)
	}
	for _, p := range data {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files["data/"+filepath.Base(p)] = b
	}
	p403, err := os.ReadFile(filepath.Join(r.opt.Home, "waf", "static", "403.html"))
	if err != nil {
		return err
	}
	p500, err := os.ReadFile(filepath.Join(r.opt.Home, "waf", "static", "500.html"))
	if err != nil {
		return err
	}
	for _, s := range r.sites {
		id := s.Eff.Site.SiteID
		b403 := p403
		if bp := s.Eff.WAF.BlockPage; bp != "" && bp != "aws" {
			b403, err = os.ReadFile(filepath.Join(r.cfg.Dir, "pages", bp))
			if err != nil {
				return fmt.Errorf("site %s block_page: %w", id, err)
			}
		}
		files["static/"+id+"/403.html"] = b403
		files["static/"+id+"/500.html"] = p500
	}
	return nil
}

// Meta is <R>/meta.json.
type Meta struct {
	NodeID     string   `json:"node_id"`
	Version    string   `json:"version"`
	ConfigRev  string   `json:"config_rev"`
	RenderedAt string   `json:"rendered_at"`
	Sites      []string `json:"sites"`
}

func (r *renderer) meta(rev string) []byte {
	m := Meta{NodeID: r.cfg.Node.NodeID, Version: r.opt.Version, ConfigRev: rev,
		RenderedAt: r.opt.Now.UTC().Format("2006-01-02T15:04:05Z"), Sites: []string{}}
	for _, s := range r.sites {
		m.Sites = append(m.Sites, s.Eff.Site.SiteID)
	}
	// Single-line JSON: the node Vector heartbeat reads it with `cat` as one event.
	b, _ := json.Marshal(m)
	return append(b, '\n')
}

// WriteTree writes out.Files under dir (files 0644, dirs 0755).
func WriteTree(out *Output, dir string) error {
	paths := make([]string, 0, len(out.Files))
	for p := range out.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, out.Files[p], 0o644); err != nil {
			return err
		}
	}
	return nil
}

var reListFile = regexp.MustCompile(`/etc/waf/lists/([A-Za-z0-9._-]+)`)

// ListFiles returns the list file names referenced by the catalog.
func ListFiles(cat *catalog.Catalog) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range cat.Rules() {
		for _, ch := range r.Detectors {
			for _, l := range ch {
				for _, m := range reListFile.FindAllStringSubmatch(l.Op, -1) {
					if !seen[m[1]] {
						seen[m[1]] = true
						out = append(out, m[1])
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// EnsureLists creates placeholder list files in listsDir; returns the created names.
func EnsureLists(cat *catalog.Catalog, listsDir string) ([]string, error) {
	if err := os.MkdirAll(listsDir, 0o755); err != nil {
		return nil, err
	}
	var created []string
	for _, n := range ListFiles(cat) {
		p := filepath.Join(listsDir, n)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		if err := os.WriteFile(p, []byte("# placeholder (wafctl)\n"), 0o644); err != nil {
			return nil, err
		}
		created = append(created, n)
	}
	return created, nil
}
