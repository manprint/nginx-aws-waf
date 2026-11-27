package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"nginxawswaf/wafctl/internal/central"
	"nginxawswaf/wafctl/internal/config"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/pki"
)

const pkiUsage = `usage: wafctl pki <command>
  init --name N                                   create the CA in $WAF_PKI_DIR (refuses if it exists)
  issue --cn CN --kind client|server [--dns D]... [--ip I]... [--out DIR]
  revoke <serial|cn>                              revoke + regenerate the CRL
  list [--format table|json]
  crl                                             regenerate the CRL (daily timer)
  token --cn CN [--ttl 24h]                       one-time enrollment token`

// pkiHooks run after the CRL changed (5.2: copy to the ingress and reload it).
var pkiAfterCRL = func(s *pki.Store) error { return nil }

func cmdPKI(args []string) int {
	if len(args) == 0 {
		return fail("%s", pkiUsage)
	}
	s := pki.Open(env.PKIDir())
	sub, rest := args[0], args[1:]
	switch sub {
	case "init":
		fs := flag.NewFlagSet("pki init", flag.ContinueOnError)
		name := fs.String("name", "", "CA name (subject CN=nginx-aws-waf CA <name>)")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if err := s.Init(*name); err != nil {
			return fail("%v", err)
		}
		ca, _ := s.CACert()
		fmt.Printf("CA created in %s\nca_sha256=%s\n", s.Dir, pki.Fingerprint(ca))
		return 0
	case "issue":
		fs := flag.NewFlagSet("pki issue", flag.ContinueOnError)
		cn := fs.String("cn", "", "common name (node_id for client certs)")
		kind := fs.String("kind", "", "client|server")
		out := fs.String("out", ".", "output directory for <cn>.pem, <cn>.key, ca.pem")
		var dns, ips multiFlag
		fs.Var(&dns, "dns", "server SAN DNS name (repeatable)")
		fs.Var(&ips, "ip", "server SAN IP (repeatable)")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		r := pki.Request{CN: *cn, Kind: *kind, DNS: dns}
		for _, i := range ips {
			ip := net.ParseIP(i)
			if ip == nil {
				return fail("--ip %q: not an IP", i)
			}
			r.IPs = append(r.IPs, ip)
		}
		is, key, err := s.Issue(r)
		if err != nil {
			return fail("%v", err)
		}
		caPEM, err := s.CAPEM()
		if err != nil {
			return fail("%v", err)
		}
		if err := writeCertFiles(*out, *cn, is.PEM, key, caPEM); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("issued %s %s serial %s not_after %s → %s\n", is.Entry.Kind, is.Entry.CN, is.Entry.Serial,
			is.Entry.NotAfter.Format(time.RFC3339), filepath.Join(*out, *cn+".{pem,key}"))
		return 0
	case "revoke":
		if len(rest) != 1 {
			return fail("usage: wafctl pki revoke <serial|cn>")
		}
		got, err := s.Revoke(rest[0])
		if err != nil {
			return fail("%v", err)
		}
		for _, g := range got {
			fmt.Println("revoked", g)
		}
		if err := pkiAfterCRL(s); err != nil {
			return fail("crl published locally, but: %v", err)
		}
		return 0
	case "crl":
		if err := s.CRL(); err != nil {
			return fail("%v", err)
		}
		c, err := s.ReadCRL()
		if err != nil {
			return fail("%v", err)
		}
		fmt.Printf("crl number %s, %d revoked, next_update %s\n", c.Number, len(c.RevokedCertificateEntries), c.NextUpdate.UTC().Format(time.RFC3339))
		if err := pkiAfterCRL(s); err != nil {
			return fail("%v", err)
		}
		return 0
	case "list":
		fs := flag.NewFlagSet("pki list", flag.ContinueOnError)
		format := fs.String("format", "table", "table|json")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		es, err := s.List()
		if err != nil {
			return fail("%v", err)
		}
		now := time.Now().UTC()
		if *format == "json" {
			type row struct {
				pki.Entry
				Status string `json:"status"`
			}
			rows := []row{}
			for _, e := range es {
				rows = append(rows, row{e, e.Status(now)})
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(rows); err != nil {
				return fail("%v", err)
			}
			return 0
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SERIAL\tCN\tKIND\tNOT_AFTER\tSTATUS")
		for _, e := range es {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Serial, e.CN, e.Kind, e.NotAfter.Format(time.RFC3339), e.Status(now))
		}
		tw.Flush()
		return 0
	case "token":
		fs := flag.NewFlagSet("pki token", flag.ContinueOnError)
		cn := fs.String("cn", "", "node_id the token is bound to")
		ttl := fs.Duration("ttl", 24*time.Hour, "validity")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		tok, fp, err := s.NewToken(*cn, *ttl)
		if err != nil {
			return fail("%v", err)
		}
		fmt.Printf("token=%s\nca_sha256=%s\n", tok, fp)
		return 0
	}
	return fail("%s", pkiUsage)
}

// writeCertFiles writes <name>.pem, <name>.key (0600) and ca.pem into dir.
func writeCertFiles(dir, name string, cert, key, ca []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range []struct {
		n    string
		b    []byte
		mode os.FileMode
	}{{name + ".key", key, 0o600}, {name + ".pem", cert, 0o644}, {"ca.pem", ca, 0o644}} {
		p := filepath.Join(dir, f.n)
		if err := os.WriteFile(p+".tmp", f.b, f.mode); err != nil {
			return err
		}
		if err := os.Chmod(p+".tmp", f.mode); err != nil {
			return err
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	pkiAfterCRL = publishCRL
}

// publishCRL copies crl.pem to the ingress certs dir and reloads the ingress when it runs.
func publishCRL(s *pki.Store) error {
	if _, err := os.Stat(central.IngressCertsDir(env.CentralDir())); err != nil {
		return nil // no ingress rendered on this host (yet): nothing to publish
	}
	changed, err := central.PublishCRL(s, env.CentralDir())
	if err != nil || !changed {
		return err
	}
	cfg, err := config.Load(env.ConfigDir())
	if err != nil {
		return fmt.Errorf("crl copied to the ingress; reload it by hand (%v)", err)
	}
	eng, err := newEngine(cfg.Node)
	if err != nil {
		return err
	}
	if up, _ := eng.Running("ingress"); !up {
		return nil
	}
	if out, err := eng.Exec("ingress", "nginx", "-c", "/etc/waf/ingress/nginx.conf", "-s", "reload"); err != nil {
		return fmt.Errorf("ingress reload: %v: %s", err, out)
	}
	fmt.Fprintln(os.Stderr, "crl published to the ingress, ingress reloaded")
	return nil
}
