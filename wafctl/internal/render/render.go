// Package render turns the catalog plus a node config into nginx + ModSecurity runtime files.
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
)

// RevPlaceholder is the rev token used while hashing.
const RevPlaceholder = "REV"

// Options controls a render.
type Options struct {
	Now         time.Time
	Version     string
	RuntimeRoot string // "/etc/waf/runtime"
	Home        string // WAF_HOME (data and static files); default env.Home()
	AuditSlot   int    // 0|1, see AuditLogPath; flipped by `wafctl logs rotate`
}

// Output is a rendered runtime tree (paths relative to the runtime dir).
type Output struct {
	Rev   string
	Files map[string][]byte
}

// site is one effective site with its D23 index.
type site struct {
	Idx int
	Eff *config.EffectiveSite
}

type renderer struct {
	cfg   *config.Config
	cat   *catalog.Catalog
	opt   Options
	R     string // runtime dir with placeholder rev
	sites []site // siteIdx order
}

// Render renders all files; bypass maps site_id → bypass active.
func Render(cfg *config.Config, cat *catalog.Catalog, bypass map[string]bool, opt Options) (*Output, error) {
	if opt.RuntimeRoot == "" {
		opt.RuntimeRoot = "/etc/waf/runtime"
	}
	if opt.Home == "" {
		h, err := env.Home()
		if err != nil {
			return nil, err
		}
		opt.Home = h
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	r := &renderer{cfg: cfg, cat: cat, opt: opt, R: opt.RuntimeRoot + "/" + RevPlaceholder}
	ids := make([]string, 0, len(cfg.Sites))
	for _, s := range cfg.Sites {
		ids = append(ids, s.SiteID)
	}
	sort.Strings(ids)
	for i, id := range ids {
		e, err := config.Effective(cfg, id, cat, bypass[id])
		if err != nil {
			return nil, err
		}
		r.sites = append(r.sites, site{Idx: i, Eff: e})
	}
	files := map[string][]byte{}
	main, err := r.mainConf()
	if err != nil {
		return nil, err
	}
	files["modsec/main.conf"] = []byte(main)
	if err := r.extraFiles(files); err != nil {
		return nil, err
	}
	// Test hook (tests/e2e/apply.sh): WAF_TEST_INJECT=1 makes nginx.conf invalid.
	if os.Getenv("WAF_TEST_INJECT") == "1" {
		files["nginx/nginx.conf"] = append(files["nginx/nginx.conf"], []byte("bogus_directive on;\n")...)
	}
	rev := opt.Now.UTC().Format("20060102T150405Z") + "-" + hashFiles(files)
	out := &Output{Rev: rev, Files: map[string][]byte{}}
	for p, b := range files {
		s := strings.ReplaceAll(string(b), r.R, opt.RuntimeRoot+"/"+rev)
		s = strings.Replace(s, " rev "+RevPlaceholder+" ", " rev "+rev+" ", 1)
		out.Files[p] = []byte(s)
	}
	out.Files["meta.json"] = r.meta(rev)
	return out, nil
}

// hashFiles returns the first 8 hex chars of sha256 over path+content, sorted by path.
// meta.json is excluded: it carries the render time and the rev itself.
func hashFiles(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		if p != "meta.json" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		fmt.Fprintf(h, "%s\x00%d\x00", p, len(files[p]))
		h.Write(files[p])
	}
	return hex.EncodeToString(h.Sum(nil))[:8]
}
