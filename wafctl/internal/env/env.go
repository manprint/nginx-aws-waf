// Package env resolves WAF_HOME, WAF_CONFIG_DIR and WAF_DATA_DIR (D19).
package env

import (
	"errors"
	"os"
	"path/filepath"
)

// CatalogRel is the catalog path relative to WAF_HOME.
const CatalogRel = "waf/catalog/rules.yaml"

// Home returns $WAF_HOME, the nearest ancestor of cwd holding waf/catalog/rules.yaml, or the
// directory of the wafctl executable (symlinks resolved: a release installed by install-node.sh).
func Home() (string, error) {
	if h := os.Getenv("WAF_HOME"); h != "" {
		return filepath.Abs(h)
	}
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, CatalogRel)); err == nil {
			return d, nil
		}
		p := filepath.Dir(d)
		if p == d {
			break
		}
		d = p
	}
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			if h := filepath.Dir(exe); fileExists(filepath.Join(h, CatalogRel)) {
				return h, nil
			}
		}
	}
	return "", errors.New("WAF_HOME not set, no ancestor of cwd and not the wafctl directory contains " + CatalogRel)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// ConfigDir returns $WAF_CONFIG_DIR (default /etc/waf-node).
func ConfigDir() string { return getenv("WAF_CONFIG_DIR", "/etc/waf-node") }

// DataDir returns $WAF_DATA_DIR (default /srv/waf).
func DataDir() string { return getenv("WAF_DATA_DIR", "/srv/waf") }

// CentralDir returns $WAF_CENTRAL_DIR (default $WAF_DATA_DIR/central).
func CentralDir() string { return getenv("WAF_CENTRAL_DIR", filepath.Join(DataDir(), "central")) }

// PKIDir returns $WAF_PKI_DIR (default $WAF_CONFIG_DIR/pki; central role only).
func PKIDir() string { return getenv("WAF_PKI_DIR", filepath.Join(ConfigDir(), "pki")) }

// SecretsFile returns $WAF_CONFIG_DIR/secrets.env.
func SecretsFile() string { return filepath.Join(ConfigDir(), "secrets.env") }

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// CatalogPath returns the catalog path under Home.
func CatalogPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, CatalogRel), nil
}
