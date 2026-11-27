package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/node"
	"nginxawswaf/wafctl/internal/pki"
)

const nodeUsage = `usage: wafctl node <command>
  enroll --token T --ca-sha256 H [--central host:pki_port]   get the client cert (one-time token)
  renew [--force] [--central host:pki_port]                  renew when < 30 d left (daily timer)
  bootstrap --node-id ID --role node|central|all-in-one [--central HOST] [--network host|bridge]
            [--install-systemd] [--force]                    create $WAF_CONFIG_DIR (git repo) and $WAF_DATA_DIR`

func cmdNode(args []string) int {
	if len(args) == 0 {
		return fail("%s", nodeUsage)
	}
	if args[0] == "bootstrap" {
		return nodeBootstrap(args[1:])
	}
	cfg, err := config.Load(env.ConfigDir())
	if err != nil {
		return fail("%v", err)
	}
	n := cfg.Node
	port := n.Central.PKIPort
	if port == 0 {
		port = 6001
	}
	def := ""
	if n.Central.Address != "" {
		def = net.JoinHostPort(n.Central.Address, strconv.Itoa(port))
	}
	dir := filepath.Join(env.DataDir(), "certs", "_node")
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("node "+sub, flag.ContinueOnError)
	cen := fs.String("central", def, "central pki API host:port (default central.address:pki_port of node.yaml)")
	switch sub {
	case "enroll":
		tok := fs.String("token", "", "one-time token (wafctl pki token on the central)")
		fp := fs.String("ca-sha256", "", "CA fingerprint printed with the token")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *cen == "" || *tok == "" {
			return fail("node enroll: --token and a central address (node.yaml central.address or --central) are required")
		}
		c, err := node.Enroll(node.EnrollOptions{Central: *cen, Token: *tok, CASHA256: *fp, CN: n.NodeID, Dir: dir})
		if err != nil {
			return fail("%v", err)
		}
		fmt.Printf("enrolled %s: serial %s, expires %s\n", n.NodeID, pki.SerialHex(c.SerialNumber), c.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	case "renew":
		force := fs.Bool("force", false, "renew even if more than 30 days are left")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *cen == "" {
			return fail("node renew: no central address (node.yaml central.address or --central)")
		}
		c, err := node.Renew(node.RenewOptions{Central: *cen, Dir: dir, Force: *force})
		if err != nil {
			return fail("%v", err)
		}
		if c == nil {
			fmt.Println("certificate valid for more than 30 days: nothing to do")
			return 0
		}
		fmt.Printf("renewed %s: serial %s, expires %s\n", n.NodeID, pki.SerialHex(c.SerialNumber), c.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	default:
		return fail("%s", nodeUsage)
	}
	// the node Vector reads the cert at start
	eng, err := newEngine(n)
	if err != nil {
		return fail("%v", err)
	}
	if up, _ := eng.Running("vector"); up {
		if err := eng.Restart("vector"); err != nil {
			return fail("restart vector: %v", err)
		}
		fmt.Fprintln(os.Stderr, "vector restarted")
	}
	return 0
}

func nodeBootstrap(args []string) int {
	fs := flag.NewFlagSet("node bootstrap", flag.ContinueOnError)
	o := node.BootstrapOptions{}
	fs.StringVar(&o.NodeID, "node-id", "", "node id (lower-case, digits, dashes)")
	fs.StringVar(&o.Role, "role", "", "node|central|all-in-one")
	fs.StringVar(&o.Central, "central", "", "central host name/IP (node.yaml central.address; ingress server name for central roles)")
	fs.StringVar(&o.Network, "network", "host", "host|bridge")
	fs.BoolVar(&o.InstallSystemd, "install-systemd", false, "install the systemd units and enable the role's timers (root)")
	fs.BoolVar(&o.Force, "force", false, "overwrite the generated files when node.yaml exists")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	home, err := env.Home()
	if err != nil {
		return fail("%v", err)
	}
	o.Home, o.ConfigDir, o.DataDir = home, env.ConfigDir(), env.DataDir()
	next, err := node.Bootstrap(o)
	if err != nil {
		return fail("%v", err)
	}
	fmt.Print(next)
	return 0
}
