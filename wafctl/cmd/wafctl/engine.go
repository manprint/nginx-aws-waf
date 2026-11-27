package main

import (
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
	return docker.NewCompose(docker.Params{Home: home, Role: n.Role, Network: n.Network, NodeID: n.NodeID,
		DataDir: env.DataDir(), ConfigDir: env.ConfigDir(), CentralDir: env.CentralDir()})
}
