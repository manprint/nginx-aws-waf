package render

import (
	"bytes"
	"strings"
	"testing"

	"nginxawswaf/wafctl/internal/config"
)

func TestC0_ForwardRender(t *testing.T) {
	rows := []struct {
		n    config.Node
		want string
	}{
		{config.Node{Role: "all-in-one", Network: "bridge"}, "vector-central:6000"},
		{config.Node{Role: "all-in-one", Network: "host"}, "127.0.0.1:6000"},
		{config.Node{Role: "node", Network: "host", Central: config.Central{Address: "10.0.0.5", IngestPort: 6000}}, "10.0.0.5:6000"},
		{config.Node{Role: "node", Network: "host"}, ""},
	}
	for _, r := range rows {
		if got := CentralAddress(&r.n); got != r.want {
			t.Errorf("%+v: address %q, want %q", r.n, got, r.want)
		}
		y := string(forwardYAML(&r.n))
		for _, tr := range []string{"fwd_events:", "fwd_matches:", "fwd_hb:"} {
			if !strings.Contains(y, tr) {
				t.Errorf("missing %s", tr)
			}
		}
		if r.want == "" {
			if !strings.Contains(y, "type: blackhole") || strings.Contains(y, "fwd_central") {
				t.Errorf("unconfigured: %s", y)
			}
		} else if !strings.Contains(y, `address: "http://`+r.want+`"`) || !strings.Contains(y, "when_full: block") {
			t.Errorf("configured: %s", y)
		}
	}
	if got := CentralAddress(&config.Node{Role: "node", Central: config.Central{Address: "fd00::5", IngestPort: 6000}}); got != "[fd00::5]:6000" {
		t.Errorf("ipv6 address: %q", got)
	}
}

func TestC0_MetaSingleLine(t *testing.T) {
	out := renderDir(t, "testdata/config")
	m := out.Files["meta.json"]
	if bytes.Count(m, []byte("\n")) != 1 || !bytes.HasSuffix(m, []byte("}\n")) {
		t.Errorf("meta.json not single-line: %q", m)
	}
	if _, ok := out.Files["vector/forward.yaml"]; !ok {
		t.Error("vector/forward.yaml not rendered")
	}
}
