package central

import (
	"bufio"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed templates/*
var tmplFS embed.FS

// Components are the rendered sub-directories of $WAF_CENTRAL_DIR, each owned by one service.
var Components = map[string]string{"prometheus": "prometheus", "grafana": "grafana", "apprise": "apprise"}

// Files returns the rendered files (path relative to $WAF_CENTRAL_DIR → content).
func Files(c Config, configDir string) (map[string][]byte, error) {
	prom, err := tmplFS.ReadFile("templates/prometheus.yml.tmpl")
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{"prometheus/prometheus.yml": prom}
	for k, v := range grafanaFiles() {
		files[k] = v
	}
	af, err := alertFiles(c, configDir)
	if err != nil {
		return nil, err
	}
	for k, v := range af {
		files[k] = v
	}
	return files, nil
}

// Render writes the files into outDir and returns the services whose files changed.
func Render(c Config, configDir, outDir string) ([]string, error) {
	files, err := Files(c, configDir)
	if err != nil {
		return nil, err
	}
	before := map[string]string{}
	for comp := range Components {
		before[comp] = filesHash(outDir, comp, files)
	}
	for p, b := range files {
		full := filepath.Join(outDir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return nil, err
		}
		if old, err := os.ReadFile(full); err == nil && string(old) == string(b) {
			continue
		}
		tmp := full + ".tmp"
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, full); err != nil {
			return nil, err
		}
	}
	var changed []string
	for comp, svc := range Components {
		if filesHash(outDir, comp, files) != before[comp] {
			changed = append(changed, svc)
		}
	}
	sort.Strings(changed)
	return changed, nil
}

// filesHash is the sha256 of the on-disk content of the rendered files of one component (only the
// files wafctl renders: service state such as prometheus/data or apprise's store and pid files
// must not trigger a restart).
func filesHash(outDir, comp string, files map[string][]byte) string {
	var paths []string
	for p := range files {
		if strings.HasPrefix(p, comp+"/") {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join(outDir, p))
		h.Write([]byte(p + "\x00"))
		if err != nil {
			h.Write([]byte("\x00missing\x00"))
		}
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ReadURLs reads one apprise URL per line, skipping blanks and # comments.
func ReadURLs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var urls []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		urls = append(urls, l)
	}
	return urls, sc.Err()
}
