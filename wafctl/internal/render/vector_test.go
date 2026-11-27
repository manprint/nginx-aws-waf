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
		{config.Node{Role: "all-in-one", Network: "host"}, "127.0.0.1:6100"},
		{config.Node{Role: "node", Network: "host", Central: config.Central{Address: "10.0.0.5", IngestPort: 6000}}, "10.0.0.5:6000"},
		{config.Node{Role: "node", Network: "host"}, ""},
	}
	for _, r := range rows {
		if got := CentralAddress(&r.n); got != r.want {
			t.Errorf("%+v: address %q, want %q", r.n, got, r.want)
		}
		y := string(forwardYAML(&r.n))
		for _, tr := range []string{"fwd_events:", "fwd_matches:", "fwd_hb:", "m_host:", "m_nginx:", "m_vector:", "m_tag:", "fwd_hb, m_tag]"} {
			if !strings.Contains(y, tr) {
				t.Errorf("missing %s", tr)
			}
		}
		if r.want == "" {
			if !strings.Contains(y, "type: blackhole") || strings.Contains(y, "fwd_central") {
				t.Errorf("unconfigured: %s", y)
			}
		} else if r.n.Role == "all-in-one" && (!strings.Contains(y, `address: "http://`+r.want+`"`) || !strings.Contains(y, "when_full: block") || strings.Contains(y, "tls:")) {
			t.Errorf("configured: %s", y)
		}
	}
	if got := CentralAddress(&config.Node{Role: "node", Central: config.Central{Address: "fd00::5", IngestPort: 6000}}); got != "[fd00::5]:6000" {
		t.Errorf("ipv6 address: %q", got)
	}
}

func TestFWD1_NodeForwardTLS(t *testing.T) {
	n := config.Node{NodeID: "lab-node-2", Role: "node", Network: "bridge", Central: config.Central{Address: "central.lab.test", IngestPort: 6000}}
	y := string(forwardYAML(&n))
	want := `  fwd_central:
    type: vector
    inputs: [fwd_events, fwd_matches, fwd_hb, m_tag]
    address: "central.lab.test:6000"
    tls: {enabled: true, crt_file: /etc/waf/certs/_node/node.pem, key_file: /etc/waf/certs/_node/node.key, ca_file: /etc/waf/certs/_node/ca.pem, verify_hostname: true}
    buffer: {type: disk, max_size: 2147483648, when_full: block}
`
	if !strings.HasSuffix(y, want) || strings.Contains(y, "http://central") {
		t.Errorf("node forward:\n%s", y)
	}
}

func TestCEN0_MetricsRender(t *testing.T) {
	b := string(forwardYAML(&config.Node{NodeID: "lab-node-1", Role: "all-in-one", Network: "bridge"}))
	h := string(forwardYAML(&config.Node{NodeID: "n1", Role: "node", Network: "host"}))
	if !strings.Contains(b, `"http://waf:8090/nginx_status"`) || !strings.Contains(b, `.tags.node_id = "lab-node-1"`) {
		t.Errorf("bridge metrics: %s", b)
	}
	if !strings.Contains(h, `"http://127.0.0.1:8090/nginx_status"`) || !strings.Contains(h, `.tags.node_id = "n1"`) {
		t.Errorf("host metrics: %s", h)
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
