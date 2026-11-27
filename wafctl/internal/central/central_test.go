package central

import (
	"bytes"
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"nginxawswaf/wafctl/internal/pki"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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
	if err != nil || strings.Join(ch, ",") != "apprise,grafana,prometheus" {
		t.Fatalf("first render changed %v %v", ch, err)
	}
	// service state next to rendered files (apprise pid/store, prometheus data) is not a change
	os.WriteFile(filepath.Join(out, "apprise", ".scheduler.pid"), []byte("1"), 0o600)
	os.MkdirAll(filepath.Join(out, "prometheus", "data"), 0o755)
	os.WriteFile(filepath.Join(out, "prometheus", "data", "x"), []byte("1"), 0o600)
	ch, _ = Render(Defaults(), t.TempDir(), out)
	if len(ch) != 0 {
		t.Errorf("second render changed %v", ch)
	}
	c := Defaults()
	c.Alerts.BlockSpikePer5m = 7
	if ch, _ = Render(c, t.TempDir(), out); strings.Join(ch, ",") != "grafana" {
		t.Errorf("threshold change restarted %v, want grafana", ch)
	}
}

func TestG1_UserAddRequestGolden(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u, p, _ := r.BasicAuth()
		got = append(got, fmt.Sprintf("%s %s auth=%s:%s %s", r.Method, r.URL.Path, u, p, b))
		if r.Method == http.MethodPost {
			w.Write([]byte(`{"id":7,"message":"User created"}`))
			return
		}
		w.Write([]byte(`{"message":"ok"}`))
	}))
	defer srv.Close()
	g := &GrafanaAPI{URL: srv.URL, User: "admin", Password: "pw"}
	id, err := g.AddUser(context.Background(), "viewer1", "Viewer One", "", "Viewer", "s3cret")
	if err != nil || id != 7 {
		t.Fatalf("id %d err %v", id, err)
	}
	golden(t, "grafana-user-add.txt", []byte(strings.Join(got, "\n")+"\n"))
	files, _ := Files(Defaults(), t.TempDir())
	ds := string(files["grafana/provisioning/datasources/waf.yaml"])
	if !strings.Contains(ds, "password: $WAF_CH_RO_PASSWORD") || !strings.Contains(ds, "uid: ch") || !strings.Contains(ds, "uid: prom") {
		t.Errorf("datasources: %s", ds)
	}
	if p, _ := RandomPassword(20); len(p) != 20 {
		t.Errorf("password length %d", len(p))
	}
}

func TestAL1_RulesGoldenDefaults(t *testing.T) {
	golden(t, "alert-rules.yaml", RulesYAML(Defaults().Alerts))
	var doc struct {
		Groups []struct {
			Rules []struct {
				UID  string `yaml:"uid"`
				Data []struct {
					Model map[string]any `yaml:"model"`
				} `yaml:"data"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(RulesYAML(Defaults().Alerts), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 1 || len(doc.Groups[0].Rules) != 5 {
		t.Fatalf("rules %+v", doc)
	}
	r := doc.Groups[0].Rules[1] // waf-fail: fail_per_5m 1 → gt 0
	c := r.Data[2].Model["conditions"].([]any)[0].(map[string]any)["evaluator"].(map[string]any)["params"].([]any)[0]
	if r.UID != "waf-fail" || c != 0 {
		t.Errorf("waf-fail threshold %v", c)
	}
	if !strings.Contains(r.Data[0].Model["rawSql"].(string), "action = 'FAIL'") {
		t.Errorf("sql %v", r.Data[0].Model["rawSql"])
	}
}

func TestAL2_AppriseSkipsComments(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "apprise-urls.txt"), []byte("# slack\n\n  json://alert-sink:8000/  \n# tgram://x/y\ngchat://a/b/c\n"), 0o600)
	files, err := Files(Defaults(), dir)
	if err != nil {
		t.Fatal(err)
	}
	got := string(files["apprise/waf.yml"])
	want := "# Rendered by wafctl central render from the apprise URLs file — do not edit.\nurls:\n  - \"json://alert-sink:8000/\":\n      - tag: waf\n  - \"gchat://a/b/c\":\n      - tag: waf\n"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	empty, _ := Files(Defaults(), t.TempDir())
	if string(empty["apprise/waf.yml"]) != "# Rendered by wafctl central render from the apprise URLs file — do not edit.\nurls: []\n" {
		t.Errorf("empty: %s", empty["apprise/waf.yml"])
	}
}

func TestING1_IngressRender(t *testing.T) {
	golden(t, "ingress-nginx.conf", IngressConf())
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	s := &pki.Store{Dir: filepath.Join(t.TempDir(), "pki"), Now: func() time.Time { return now }}
	if err := s.Init("t"); err != nil {
		t.Fatal(err)
	}
	c := Defaults()
	c.Ingress.ServerNames = []string{"central.lab.test", "ingress"}
	out := t.TempDir()
	if ch, err := RenderIngress(c, s, out, now); err != nil || !ch {
		t.Fatalf("first render %v %v", ch, err)
	}
	dir := IngressCertsDir(out)
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "ca.pem,crl.pem,ingress.key,ingress.pem" {
		t.Errorf("certs dir %v (the CA key must never be copied)", names)
	}
	if st, _ := os.Stat(filepath.Join(dir, "ingress.key")); st.Mode() != 0o600 {
		t.Errorf("ingress.key mode %v", st.Mode())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "ingress.pem"))
	cert, _ := pki.ParseCertPEM(b)
	if strings.Join(cert.DNSNames, ",") != "central.lab.test,ingress" || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("sans %v eku %v", cert.DNSNames, cert.ExtKeyUsage)
	}
	if ch, _ := RenderIngress(c, s, out, now); ch {
		t.Errorf("second render changed")
	}
	c.Ingress.ServerIPs = []string{"192.0.2.10"}
	if ch, _ := RenderIngress(c, s, out, now); !ch {
		t.Errorf("SAN change did not reissue")
	}
	if ch, _ := RenderIngress(c, s, out, now.Add(61*24*time.Hour)); !ch {
		t.Errorf("expiring cert (29 d left) not reissued")
	}
	s.Revoke("ingress")
	if ch, _ := PublishCRL(s, out); !ch {
		t.Errorf("new CRL not published")
	}
	if ch, _ := PublishCRL(s, out); ch {
		t.Errorf("unchanged CRL republished")
	}
	pb, _ := os.ReadFile(filepath.Join(s.Dir, "crl.pem"))
	ib, _ := os.ReadFile(filepath.Join(dir, "crl.pem"))
	if !bytes.Equal(pb, ib) {
		t.Errorf("published crl differs")
	}
	c.Ingress.Bind = "x"
	if errs, _ := c.Validate(t.TempDir()); len(errs) == 0 {
		t.Errorf("bad ingress.bind accepted")
	}
}
