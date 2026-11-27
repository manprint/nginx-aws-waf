package node

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"nginxawswaf/wafctl/internal/pki"
)

// RenewOptions: Central is host:pki_port; Now nil → time.Now.
type RenewOptions struct {
	Central, Dir string
	Force        bool
	Now          func() time.Time
}

// Renew replaces node.pem/node.key when the cert expires in < 30 d (or Force), over mTLS with the
// current cert. Returns the new cert, or nil when no renewal was needed.
func Renew(o RenewOptions) (*x509.Certificate, error) {
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	certPEM, err := os.ReadFile(filepath.Join(o.Dir, CertFile))
	if err != nil {
		return nil, fmt.Errorf("renew: %w (enroll first: wafctl node enroll)", err)
	}
	cur, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if !o.Force && cur.NotAfter.Sub(now) > pki.RenewBefore {
		return nil, nil
	}
	caPEM, err := os.ReadFile(filepath.Join(o.Dir, CAFile))
	if err != nil {
		return nil, err
	}
	ca, err := pki.ParseCertPEM(caPEM)
	if err != nil {
		return nil, err
	}
	kp, err := tls.LoadX509KeyPair(filepath.Join(o.Dir, CertFile), filepath.Join(o.Dir, KeyFile))
	if err != nil {
		return nil, err
	}
	key, csr, err := pki.NewCSR(cur.Subject.CommonName)
	if err != nil {
		return nil, err
	}
	cert, _, err := post(client(ca, []tls.Certificate{kp}), "https://"+o.Central+"/renew", pki.RenewRequest{CSR: string(csr)})
	if err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	return install(o.Dir, key, cert, caPEM, ca, cur.Subject.CommonName)
}
