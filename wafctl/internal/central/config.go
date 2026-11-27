// Package central holds the central-stack config ($WAF_CONFIG_DIR/central.yaml) and renders the
// files of Prometheus, Grafana and apprise into $WAF_CENTRAL_DIR.
package central

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config is central.yaml.
type Config struct {
	Version    int        `yaml:"version"`
	Grafana    Grafana    `yaml:"grafana"`
	Alerts     Alerts     `yaml:"alerts"`
	Apprise    Apprise    `yaml:"apprise"`
	ClickHouse ClickHouse `yaml:"clickhouse"`
	Ingress    Ingress    `yaml:"ingress"`
	File       string     `yaml:"-"`
}

// Grafana is where Grafana listens.
type Grafana struct {
	Bind    string `yaml:"bind"`
	RootURL string `yaml:"root_url"`
}

// Alerts are the alert thresholds.
type Alerts struct {
	BlockSpikePer5m   int `yaml:"block_spike_per_5m"`
	FailPer5m         int `yaml:"fail_per_5m"`
	NodeSilentMin     int `yaml:"node_silent_min"`
	IngestLagMin      int `yaml:"ingest_lag_min"`
	DisagreementPer5m int `yaml:"disagreement_per_5m"`
}

// Apprise points to the apprise URL list.
type Apprise struct {
	URLsFile string `yaml:"urls_file"`
}

// ClickHouse retention (days).
type ClickHouse struct {
	RawDays int `yaml:"raw_days"`
	AggDays int `yaml:"agg_days"`
}

// FileName is the config file name in $WAF_CONFIG_DIR.
const FileName = "central.yaml"

// Defaults returns the built-in defaults.
func Defaults() Config {
	return Config{Version: 1,
		Grafana:    Grafana{Bind: "127.0.0.1:3000", RootURL: "http://localhost:3000/"},
		Alerts:     Alerts{BlockSpikePer5m: 500, FailPer5m: 1, NodeSilentMin: 3, IngestLagMin: 5, DisagreementPer5m: 200},
		Apprise:    Apprise{URLsFile: "apprise-urls.txt"},
		ClickHouse: ClickHouse{RawDays: 30, AggDays: 400},
		Ingress:    Ingress{Bind: "0.0.0.0", IngestPort: 6000, PKIPort: 6001, ServerNames: []string{"central.example.com"}},
	}
}

// Load reads <dir>/central.yaml over the defaults (strict: unknown keys are errors).
// A missing file yields the defaults.
func Load(dir string) (Config, error) {
	c := Defaults()
	p := filepath.Join(dir, FileName)
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	c, err = Parse(b)
	c.File = p
	return c, err
}

// Parse decodes central.yaml content over the defaults.
func Parse(b []byte) (Config, error) {
	c := Defaults()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return c, fmt.Errorf("%s: %w", FileName, err)
	}
	return c, nil
}

// Validate returns the problems of c (errors) and warnings.
func (c Config) Validate(configDir string) (errs, warns []string) {
	if c.Version != 1 {
		errs = append(errs, fmt.Sprintf("version %d not supported (want 1)", c.Version))
	}
	if h, p, err := net.SplitHostPort(c.Grafana.Bind); err != nil || net.ParseIP(h) == nil {
		errs = append(errs, fmt.Sprintf("grafana.bind %q: want IP:port", c.Grafana.Bind))
	} else if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
		errs = append(errs, fmt.Sprintf("grafana.bind %q: bad port", c.Grafana.Bind))
	}
	if u, err := url.Parse(c.Grafana.RootURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, fmt.Sprintf("grafana.root_url %q: want an http(s) URL", c.Grafana.RootURL))
	}
	a := c.Alerts
	for _, x := range []struct {
		n string
		v int
	}{{"block_spike_per_5m", a.BlockSpikePer5m}, {"fail_per_5m", a.FailPer5m}, {"node_silent_min", a.NodeSilentMin},
		{"ingest_lag_min", a.IngestLagMin}, {"disagreement_per_5m", a.DisagreementPer5m}} {
		if x.v < 1 {
			errs = append(errs, fmt.Sprintf("alerts.%s must be >= 1", x.n))
		}
	}
	if c.ClickHouse.RawDays < 1 || c.ClickHouse.RawDays > 3650 {
		errs = append(errs, "clickhouse.raw_days must be 1-3650")
	}
	if c.ClickHouse.AggDays < c.ClickHouse.RawDays || c.ClickHouse.AggDays > 3650 {
		errs = append(errs, "clickhouse.agg_days must be >= raw_days and <= 3650")
	}
	errs = append(errs, c.Ingress.validate()...)
	if c.Apprise.URLsFile == "" || filepath.IsAbs(c.Apprise.URLsFile) || filepath.Base(c.Apprise.URLsFile) != c.Apprise.URLsFile {
		errs = append(errs, fmt.Sprintf("apprise.urls_file %q: want a file name in $WAF_CONFIG_DIR", c.Apprise.URLsFile))
	} else if urls, err := ReadURLs(filepath.Join(configDir, c.Apprise.URLsFile)); err != nil || len(urls) == 0 {
		warns = append(warns, fmt.Sprintf("apprise.urls_file %s: no URLs, alerts will not be delivered", c.Apprise.URLsFile))
	}
	return errs, warns
}
