// Package env resolves WAF_HOME, WAF_CONFIG_DIR and WAF_DATA_DIR (D19).
package env

import (
	"errors"
	"os"
	"path/filepath"
)

// CatalogRel is the catalog path relative to WAF_HOME.
const CatalogRel = "waf/catalog/rules.yaml"

// Home returns $WAF_HOME or the nearest ancestor of cwd holding waf/catalog/rules.yaml.
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
			return "", errors.New("WAF_HOME not set and no ancestor of cwd contains " + CatalogRel)
		}
		d = p
	}
}

// ConfigDir returns $WAF_CONFIG_DIR (default /etc/waf-node).
func ConfigDir() string { return getenv("WAF_CONFIG_DIR", "/etc/waf-node") }

// DataDir returns $WAF_DATA_DIR (default /srv/waf).
func DataDir() string { return getenv("WAF_DATA_DIR", "/srv/waf") }

// CentralDir returns $WAF_CENTRAL_DIR (default $WAF_DATA_DIR/central).
func CentralDir() string { return getenv("WAF_CENTRAL_DIR", filepath.Join(DataDir(), "central")) }

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
