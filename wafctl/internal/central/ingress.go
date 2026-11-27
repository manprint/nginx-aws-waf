package central

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"nginxawswaf/wafctl/internal/pki"
)

// Ingress is the mTLS entry point of the central (nginx stream → vector-central).
type Ingress struct {
	Bind        string   `yaml:"bind"`
	IngestPort  int      `yaml:"ingest_port"`
	PKIPort     int      `yaml:"pki_port"`
	ServerNames []string `yaml:"server_names"`
	ServerIPs   []string `yaml:"server_ips"`
}

// IngressCertName is the CN of the ingress (and pki serve) server certificate.
const IngressCertName = "ingress"

func (in Ingress) validate() (errs []string) {
	if net.ParseIP(in.Bind) == nil {
		errs = append(errs, fmt.Sprintf("ingress.bind %q: want an IP", in.Bind))
	}
	for _, p := range []struct {
		n string
		v int
	}{{"ingest_port", in.IngestPort}, {"pki_port", in.PKIPort}} {
		if p.v < 1 || p.v > 65535 {
			errs = append(errs, fmt.Sprintf("ingress.%s %d: want 1-65535", p.n, p.v))
		}
	}
	if in.IngestPort == in.PKIPort {
		errs = append(errs, "ingress.ingest_port and pki_port must differ")
	}
	for _, ip := range in.ServerIPs {
		if net.ParseIP(ip) == nil {
			errs = append(errs, fmt.Sprintf("ingress.server_ips: %q is not an IP", ip))
		}
	}
	if len(in.ServerNames)+len(in.ServerIPs) == 0 {
		errs = append(errs, "ingress: set server_names or server_ips (the names nodes use in central.address)")
	}
	return errs
}

// SANs are the DNS names of the ingress certificate: server_names + "ingress" (sorted, unique).
func (in Ingress) SANs() []string {
	set := map[string]bool{IngressCertName: true}
	for _, n := range in.ServerNames {
		set[n] = true
	}
	var out []string
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// IngressConf is $WAF_CENTRAL_DIR/ingress/nginx.conf (R10 probe shape).
func IngressConf() []byte {
	return []byte(`# Rendered by wafctl central render — do not edit.
# mTLS ingress (R10): node Vector (vector sink, tls) → here → plain vector-central:6000.
# An expired CRL makes nginx reject every client: wafctl pki crl runs daily (CRL valid 7 d).
worker_processes 1;
pid /tmp/nginx-ingress.pid;
error_log /dev/stderr notice;
events { worker_connections 4096; }
stream {
    log_format ingress '$time_iso8601 $remote_addr "$ssl_client_s_dn" $ssl_client_verify $status $bytes_received $bytes_sent $session_time';
    access_log /dev/stdout ingress;
    server {
        listen 6000 ssl;
        listen [::]:6000 ssl;
        ssl_alpn h2;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_certificate /etc/waf/pki/ingress.pem;
        ssl_certificate_key /etc/waf/pki/ingress.key;
        ssl_verify_client on;
        ssl_verify_depth 1;
        ssl_client_certificate /etc/waf/pki/ca.pem;
        ssl_crl /etc/waf/pki/crl.pem;
        proxy_pass vector-central:6000;
        proxy_connect_timeout 5s;
        proxy_timeout 10m;
    }
}
`)
}

// IngressCertsDir is where the ingress container reads its certs (only these 4 files; never the CA key).
func IngressCertsDir(outDir string) string { return filepath.Join(outDir, "ingress", "certs") }

// RenderIngress writes ingress/nginx.conf and ingress/certs/{ingress.pem,ingress.key,ca.pem,crl.pem}.
// The server cert is (re)issued when missing, expiring in < 30 d, not from this CA, or when the SANs
// changed. Returns whether the ingress must be restarted.
func RenderIngress(c Config, s *pki.Store, outDir string, now time.Time) (bool, error) {
	ca, err := s.CACert()
	if err != nil {
		return false, err
	}
	dir := IngressCertsDir(outDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	changed := false
	conf := filepath.Join(outDir, "ingress", "nginx.conf")
	if old, err := os.ReadFile(conf); err != nil || !bytes.Equal(old, IngressConf()) {
		if err := writeFile(conf, IngressConf(), 0o644); err != nil {
			return false, err
		}
		changed = true
	}
	if needServerCert(filepath.Join(dir, "ingress.pem"), ca, c.Ingress, now) {
		r := pki.Request{CN: IngressCertName, Kind: "server", DNS: c.Ingress.SANs()}
		for _, ip := range c.Ingress.ServerIPs {
			r.IPs = append(r.IPs, net.ParseIP(ip))
		}
		is, key, err := s.Issue(r)
		if err != nil {
			return false, err
		}
		if err := writeFile(filepath.Join(dir, "ingress.key"), key, 0o600); err != nil {
			return false, err
		}
		if err := writeFile(filepath.Join(dir, "ingress.pem"), is.PEM, 0o644); err != nil {
			return false, err
		}
		changed = true
	}
	caPEM, err := s.CAPEM()
	if err != nil {
		return false, err
	}
	if old, err := os.ReadFile(filepath.Join(dir, "ca.pem")); err != nil || !bytes.Equal(old, caPEM) {
		if err := writeFile(filepath.Join(dir, "ca.pem"), caPEM, 0o644); err != nil {
			return false, err
		}
		changed = true
	}
	if _, err := PublishCRL(s, outDir); err != nil {
		return false, err
	}
	return changed, nil
}

// PublishCRL copies the PKI crl.pem into the ingress certs dir; reports whether it changed.
func PublishCRL(s *pki.Store, outDir string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "crl.pem"))
	if err != nil {
		return false, err
	}
	p := filepath.Join(IngressCertsDir(outDir), "crl.pem")
	if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, b) {
		return false, nil
	}
	return true, writeFile(p, b, 0o644)
}

func needServerCert(path string, ca *x509.Certificate, in Ingress, now time.Time) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	c, err := pki.ParseCertPEM(b)
	if err != nil || c.CheckSignatureFrom(ca) != nil || c.NotAfter.Sub(now) < pki.RenewBefore {
		return true
	}
	have := append([]string(nil), c.DNSNames...)
	sort.Strings(have)
	want := in.SANs()
	if fmt.Sprint(have) != fmt.Sprint(want) {
		return true
	}
	var haveIP, wantIP []string
	for _, ip := range c.IPAddresses {
		haveIP = append(haveIP, ip.String())
	}
	for _, ip := range in.ServerIPs {
		wantIP = append(wantIP, net.ParseIP(ip).String())
	}
	sort.Strings(haveIP)
	sort.Strings(wantIP)
	return fmt.Sprint(haveIP) != fmt.Sprint(wantIP)
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
