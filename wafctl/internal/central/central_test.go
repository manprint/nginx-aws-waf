package central

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("%s: golden mismatch\n%s", name, got)
	}
}

func TestCEN1_DefaultsAndStrictDecode(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir) // no file → defaults
	if err != nil {
		t.Fatal(err)
	}
	d := Defaults()
	if c.Grafana.Bind != "127.0.0.1:3000" || c.Alerts.BlockSpikePer5m != 500 || c.Alerts.FailPer5m != 1 || c.Alerts.NodeSilentMin != 3 ||
		c.Alerts.IngestLagMin != 5 || c.Alerts.DisagreementPer5m != 200 || c.Apprise.URLsFile != "apprise-urls.txt" ||
		c.ClickHouse.RawDays != 30 || c.ClickHouse.AggDays != 400 || c.Grafana.RootURL != "http://localhost:3000/" || c.Version != d.Version {
		t.Errorf("defaults: %+v", c)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte("version: 1\nalerts: {block_spike_per_5m: 20}\n"), 0o644)
	c, err = Load(dir)
	if err != nil || c.Alerts.BlockSpikePer5m != 20 || c.Alerts.FailPer5m != 1 {
		t.Errorf("partial override: %+v %v", c.Alerts, err)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte("version: 1\nalerts: {block_spike: 20}\n"), 0o644)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "block_spike") {
		t.Errorf("unknown key accepted: %v", err)
	}
	errs, warns := Defaults().Validate(dir)
	if len(errs) != 0 || len(warns) != 1 || !strings.Contains(warns[0], "alerts will not be delivered") {
		t.Errorf("validate defaults: %v %v", errs, warns)
	}
	bad := Defaults()
	bad.Grafana.Bind = "localhost:3000"
	bad.ClickHouse.AggDays = 10
	bad.Apprise.URLsFile = "../x"
	if errs, _ := bad.Validate(dir); len(errs) != 3 {
		t.Errorf("bad config errors: %v", errs)
	}
}

func TestCEN2_PrometheusGolden(t *testing.T) {
	files, err := Files(Defaults(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "prometheus.yml", files["prometheus/prometheus.yml"])
	out := t.TempDir()
	ch, err := Render(Defaults(), t.TempDir(), out)
	if err != nil || len(ch) != 1 || ch[0] != "prometheus" {
		t.Fatalf("first render changed %v %v", ch, err)
	}
	ch, _ = Render(Defaults(), t.TempDir(), out)
	if len(ch) != 0 {
		t.Errorf("second render changed %v", ch)
	}
}
