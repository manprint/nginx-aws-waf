// Package apply validates, renders, tests and activates a runtime (I-5: a failed apply keeps the running config).
package apply

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"nginxawswaf/wafctl/internal/bypass"
	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/docker"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/render"
	"nginxawswaf/wafctl/internal/version"
)

// ErrInvalid means validation errors (exit 2).
var ErrInvalid = errors.New("configuration has validation errors")

// Prepared is a validated and rendered config.
type Prepared struct {
	Cfg      *config.Config
	Cat      *catalog.Catalog
	Issues   []config.Issue
	Bypass   map[string]bool
	Out      *render.Output
	Warnings []string
}

// Prepare loads the catalog and config, validates, reads the bypass state and renders.
func Prepare(configDir string, now time.Time) (*Prepared, error) {
	cp, err := env.CatalogPath()
	if err != nil {
		return nil, err
	}
	cat, err := catalog.Load(cp)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(configDir)
	if err != nil {
		return nil, err
	}
	p := &Prepared{Cfg: cfg, Cat: cat, Issues: config.Validate(cfg, cat)}
	if config.HasErrors(p.Issues) {
		return p, ErrInvalid
	}
	st, err := bypass.Load(bypass.Path(configDir))
	if err != nil {
		return nil, err
	}
	p.Bypass = st.Active(now)
	lists := filepath.Join(env.DataDir(), "lists")
	created, err := render.EnsureLists(cat, lists)
	if err != nil {
		return nil, err
	}
	for _, n := range created {
		p.Warnings = append(p.Warnings, fmt.Sprintf("list %s missing; created placeholder in %s", n, lists))
	}
	p.Out, err = render.Render(cfg, cat, p.Bypass, render.Options{Now: now, Version: version.Version, AuditSlot: ReadAuditSlot(env.DataDir())})
	return p, err
}

// AuditSlotPath is the file holding the audit log slot (see render.AuditLogPath).
func AuditSlotPath(dataDir string) string { return filepath.Join(dataDir, "state", "audit-slot") }

// ReadAuditSlot returns 0 or 1 (0 when the file is missing).
func ReadAuditSlot(dataDir string) int {
	b, err := os.ReadFile(AuditSlotPath(dataDir))
	if err == nil && strings.TrimSpace(string(b)) == "1" {
		return 1
	}
	return 0
}

// WriteAuditSlot stores the slot.
func WriteAuditSlot(dataDir string, slot int) error {
	if err := os.MkdirAll(filepath.Dir(AuditSlotPath(dataDir)), 0o755); err != nil {
		return err
	}
	return os.WriteFile(AuditSlotPath(dataDir), []byte(fmt.Sprintf("%d\n", slot%2)), 0o644)
}

// Options tunes Apply.
type Options struct {
	DryRun        bool
	HealthTimeout time.Duration
	Keep          int
	Log           func(string)
}

// Apply writes the rev, runs nginx -t, switches current and reloads or starts the node.
func Apply(p *Prepared, eng docker.Engine, runtimeDir string, o Options) (string, error) {
	if o.HealthTimeout == 0 {
		o.HealthTimeout = 60 * time.Second
	}
	if o.Keep == 0 {
		o.Keep = 5
	}
	logf := func(f string, a ...any) {
		if o.Log != nil {
			o.Log(fmt.Sprintf(f, a...))
		}
	}
	rev := p.Out.Rev
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return "", err
	}
	revDir := filepath.Join(runtimeDir, rev)
	created := false
	if _, err := os.Stat(revDir); err != nil {
		tmp := revDir + ".tmp"
		_ = os.RemoveAll(tmp)
		if err := render.WriteTree(p.Out, tmp); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, revDir); err != nil {
			return "", err
		}
		created = true
	}
	conf := "/etc/waf/runtime/" + rev + "/nginx/nginx.conf"
	running, err := eng.Running("waf")
	if err != nil {
		return "", err
	}
	var out string
	if running {
		out, err = eng.Exec("waf", "nginx", "-t", "-q", "-c", conf)
	} else {
		out, err = eng.RunOnce("waf", "nginx", "-t", "-q", "-c", conf)
	}
	if err != nil {
		if created {
			_ = os.RemoveAll(revDir)
		}
		return "", fmt.Errorf("nginx -t failed for %s: %v\n%s", rev, err, out)
	}
	logf("nginx -t ok for %s", rev)
	if o.DryRun {
		return rev, nil
	}
	cur := filepath.Join(runtimeDir, "current")
	// node Vector reads runtime/current/vector/forward.yaml only at start: restart it on change
	prevFwd, _ := os.ReadFile(filepath.Join(cur, "vector", "forward.yaml"))
	fwdChanged := !bytes.Equal(prevFwd, p.Out.Files["vector/forward.yaml"])
	prevRev, _ := os.Readlink(cur)
	_ = os.Remove(cur + ".new")
	if err := os.Symlink(rev, cur+".new"); err != nil {
		return "", err
	}
	if err := os.Rename(cur+".new", cur); err != nil {
		return "", err
	}
	if running {
		if out, err := eng.Exec("waf", "nginx", "-s", "reload", "-c", "/etc/waf/runtime/current/nginx/nginx.conf"); err != nil {
			return "", fmt.Errorf("nginx reload: %v\n%s", err, out)
		}
		// reload is asynchronous: wait until the workers serve the new rev
		deadline := time.Now().Add(15 * time.Second)
		for {
			out, _ := eng.Exec("waf", "wget", "-qO-", "http://127.0.0.1:8090/__rev")
			if strings.Contains(out, rev) {
				break
			}
			if time.Now().After(deadline) {
				// the running nginx kept the old rev (e.g. a listen address it cannot bind on reload):
				// point current back to it so files and the running config agree
				if prevRev != "" && prevRev != rev {
					_ = os.Remove(cur + ".new")
					if os.Symlink(prevRev, cur+".new") == nil && os.Rename(cur+".new", cur) == nil {
						return "", fmt.Errorf("nginx did not load %s within 15s after reload; current restored to %s (see logs/error.log; a changed listen address needs a container restart: docker compose restart waf, then apply again)", rev, prevRev)
					}
				}
				return "", fmt.Errorf("nginx did not load %s within 15s after reload", rev)
			}
			time.Sleep(100 * time.Millisecond)
		}
		if fwdChanged {
			if vr, _ := eng.Running("vector"); vr {
				if err := eng.Restart("vector"); err != nil {
					return "", fmt.Errorf("vector restart: %v", err)
				}
				logf("vector restarted (forward config changed)")
			}
		}
	} else {
		if err := eng.Up(); err != nil {
			return "", err
		}
		deadline := time.Now().Add(o.HealthTimeout)
		for {
			h, _ := eng.Health("waf")
			if h == "healthy" {
				break
			}
			if time.Now().After(deadline) {
				return "", fmt.Errorf("waf not healthy after %s (status %q)", o.HealthTimeout, h)
			}
			time.Sleep(time.Second)
		}
	}
	if err := Prune(runtimeDir, o.Keep); err != nil {
		logf("prune: %v", err)
	}
	return rev, nil
}

var reRev = regexp.MustCompile(`^\d{8}T\d{6}Z-[0-9a-f]{8}$`)

// Prune keeps the newest keep rev dirs plus the current target.
func Prune(runtimeDir string, keep int) error {
	ents, err := os.ReadDir(runtimeDir)
	if err != nil {
		return err
	}
	cur, _ := os.Readlink(filepath.Join(runtimeDir, "current"))
	var revs []string
	for _, e := range ents {
		if e.IsDir() && reRev.MatchString(e.Name()) {
			revs = append(revs, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(revs)))
	for i, r := range revs {
		if i < keep || r == cur {
			continue
		}
		if err := os.RemoveAll(filepath.Join(runtimeDir, r)); err != nil {
			return err
		}
	}
	return nil
}

// reRevAny matches a rev anywhere in text (diff normalization).
var reRevAny = regexp.MustCompile(`\d{8}T\d{6}Z-[0-9a-f]{8}`)

// Normalize replaces every rev with REV.
func Normalize(s string) string { return reRevAny.ReplaceAllString(s, "REV") }

// CopyNormalized copies a runtime tree replacing revs with REV (text files only).
func CopyNormalized(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(t, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !strings.HasSuffix(p, ".data") {
			b = []byte(Normalize(string(b)))
		}
		return os.WriteFile(t, b, 0o644)
	})
}
