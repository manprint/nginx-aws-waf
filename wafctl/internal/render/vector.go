package render

import (
	"fmt"
	"net"
	"strconv"

	"nginxawswaf/wafctl/internal/config"
)

// CentralAddress resolves where the node Vector forwards to ("" = not configured).
//
//	all-in-one + bridge → vector-central:6000
//	all-in-one + host   → 127.0.0.1:6100 (central.host.yml; 6000 is the mTLS ingress)
//	node, central.address set → <address>:<ingest_port>
//	otherwise → ""
func CentralAddress(n *config.Node) string {
	switch {
	case n.Role == "all-in-one" && n.Network == "host":
		return "127.0.0.1:6100"
	case n.Role == "all-in-one":
		return "vector-central:6000"
	case n.Role == "node" && n.Central.Address != "":
		port := n.Central.IngestPort
		if port == 0 {
			port = 6000
		}
		return net.JoinHostPort(n.Central.Address, strconv.Itoa(port))
	}
	return ""
}

const forwardTransforms = `  fwd_events: {type: remap, inputs: [events_out], source: '._t = "event"'}
  fwd_matches: {type: remap, inputs: [matches_out], source: '._t = "match"'}
  fwd_hb: {type: remap, inputs: [hb_parse], source: '._t = "hb"'}
`

// NginxStatusURL is the stub_status URL as seen by the node Vector.
func NginxStatusURL(n *config.Node) string {
	if n.Network == "bridge" {
		return "http://waf:8090/nginx_status"
	}
	return "http://127.0.0.1:8090/nginx_status"
}

// metricsYAML: node health metrics, tagged with node_id (literal values: no env interpolation).
func metricsYAML(n *config.Node) (sources, transforms string) {
	sources = fmt.Sprintf(`sources:
  m_host: {type: host_metrics, collectors: [cpu, memory, load, filesystem, network], scrape_interval_secs: 15}
  m_nginx: {type: nginx_metrics, endpoints: [%q], scrape_interval_secs: 15}
  m_vector: {type: internal_metrics, scrape_interval_secs: 15}
`, NginxStatusURL(n))
	transforms = fmt.Sprintf("  m_tag: {type: remap, inputs: [m_host, m_nginx, m_vector], source: '.tags.node_id = %s'}\n", strconv.Quote(n.NodeID))
	return
}

// NodeCertDir is where the node Vector reads its client cert (mounted from $WAF_DATA_DIR/certs/_node).
const NodeCertDir = "/etc/waf/certs/_node"

// forwardYAML renders vector/forward.yaml (extra config of the node Vector).
// role node → mTLS to the central ingress (D26/R10); all-in-one → plain to the local vector-central.
func forwardYAML(n *config.Node) []byte {
	addr := CentralAddress(n)
	src, mt := metricsYAML(n)
	s := "# Rendered by wafctl: node metrics + node Vector → central forwarding.\n" + src + "transforms:\n" + forwardTransforms + mt + "sinks:\n"
	if addr == "" {
		s += "  fwd_none: {type: blackhole, inputs: [fwd_events, fwd_matches, fwd_hb, m_tag], print_interval_secs: 0}\n"
		return []byte(s)
	}
	if n.Role == "node" {
		s += fmt.Sprintf(`  fwd_central:
    type: vector
    inputs: [fwd_events, fwd_matches, fwd_hb, m_tag]
    address: %q
    tls: {enabled: true, crt_file: %s/node.pem, key_file: %s/node.key, ca_file: %s/ca.pem, verify_hostname: true}
    buffer: {type: disk, max_size: 2147483648, when_full: block}
`, addr, NodeCertDir, NodeCertDir, NodeCertDir)
		return []byte(s)
	}
	s += fmt.Sprintf(`  fwd_central:
    type: vector
    inputs: [fwd_events, fwd_matches, fwd_hb, m_tag]
    address: "http://%s"
    buffer: {type: disk, max_size: 2147483648, when_full: block}
`, addr)
	return []byte(s)
}
