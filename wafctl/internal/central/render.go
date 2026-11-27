package central

import (
	"bufio"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed templates/*
var tmplFS embed.FS

// Components are the rendered sub-directories of $WAF_CENTRAL_DIR, each owned by one service.
var Components = map[string]string{"prometheus": "prometheus"}

// Files returns the rendered files (path relative to $WAF_CENTRAL_DIR → content).
func Files(c Config, configDir string) (map[string][]byte, error) {
	prom, err := tmplFS.ReadFile("templates/prometheus.yml.tmpl")
	if err != nil {
		return nil, err
	}
	return map[string][]byte{"prometheus/prometheus.yml": prom}, nil
}

// Render writes the files into outDir and returns the services whose files changed.
func Render(c Config, configDir, outDir string) ([]string, error) {
	files, err := Files(c, configDir)
	if err != nil {
		return nil, err
	}
	before := map[string]string{}
	for comp := range Components {
		before[comp] = dirHash(filepath.Join(outDir, comp))
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
		if dirHash(filepath.Join(outDir, comp)) != before[comp] {
			changed = append(changed, svc)
		}
	}
	sort.Strings(changed)
	return changed, nil
}

// dirHash is the sha256 of all file paths and contents under dir (data/ excluded: service state).
func dirHash(dir string) string {
	h := sha256.New()
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() && (rel == "data") {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			b, _ := os.ReadFile(p)
			h.Write([]byte(rel + "\x00"))
			h.Write(b)
		}
		return nil
	})
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
