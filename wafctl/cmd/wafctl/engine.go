package main

import (
	"fmt"
	"nginxawswaf/wafctl/internal/central"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/docker"
	"nginxawswaf/wafctl/internal/env"
)

// newEngine returns the compose engine for the node's role and network.
func newEngine(n *config.Node) (*docker.Compose, error) {
	home, err := env.Home()
	if err != nil {
		return nil, err
	}
	extra := []string{fmt.Sprintf("WAF_HTTP_PORT=%d", n.Listen.HTTP), fmt.Sprintf("WAF_HTTPS_PORT=%d", n.Listen.HTTPS)}
	if n.Role == "central" || n.Role == "all-in-one" {
		c, err := central.Load(env.ConfigDir())
		if err != nil {
			return nil, err
		}
		extra = append(extra, "GF_BIND="+c.Grafana.Bind, "GF_ROOT_URL="+c.Grafana.RootURL,
			"INGRESS_BIND="+c.Ingress.Bind, fmt.Sprintf("INGRESS_PORT=%d", c.Ingress.IngestPort))
	}
	return docker.NewCompose(docker.Params{Home: home, Role: n.Role, Network: n.Network, NodeID: n.NodeID,
		DataDir: env.DataDir(), ConfigDir: env.ConfigDir(), CentralDir: env.CentralDir(), Extra: extra})
}
