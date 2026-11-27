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
//	all-in-one + host   → 127.0.0.1:6000
//	node, central.address set → <address>:<ingest_port>
//	otherwise → ""
func CentralAddress(n *config.Node) string {
	switch {
	case n.Role == "all-in-one" && n.Network == "host":
		return "127.0.0.1:6000"
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

const forwardTransforms = `transforms:
  fwd_events: {type: remap, inputs: [events_out], source: '._t = "event"'}
  fwd_matches: {type: remap, inputs: [matches_out], source: '._t = "match"'}
  fwd_hb: {type: remap, inputs: [hb_parse], source: '._t = "hb"'}
`

// forwardYAML renders vector/forward.yaml (extra config of the node Vector).
// The vector sink defaults to TLS without a scheme: plain http:// until P5 adds mTLS.
func forwardYAML(n *config.Node) []byte {
	addr := CentralAddress(n)
	s := "# Rendered by wafctl: node Vector → central forwarding.\n" + forwardTransforms + "sinks:\n"
	if addr == "" {
		s += "  fwd_none: {type: blackhole, inputs: [fwd_events, fwd_matches, fwd_hb], print_interval_secs: 0}\n"
		return []byte(s)
	}
	s += fmt.Sprintf(`  fwd_central:
    type: vector
    inputs: [fwd_events, fwd_matches, fwd_hb]
    address: "http://%s"
    buffer: {type: disk, max_size: 2147483648, when_full: block}
`, addr)
	return []byte(s)
}
