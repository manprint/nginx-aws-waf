// Package node is the node side of the PKI: enroll (token + pinned CA) and renew (mTLS).
package node

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxawswaf/wafctl/internal/pki"
)

// Timeout of every request to the central pki API.
const Timeout = 15 * time.Second

// Files of the node client certificate in the cert dir ($WAF_DATA_DIR/certs/_node).
const (
	CertFile = "node.pem"
	KeyFile  = "node.key"
	CAFile   = "ca.pem"
)

// EnrollOptions: Central is host:pki_port, CN the node_id.
type EnrollOptions struct {
	Central, Token, CASHA256, CN, Dir string
}

// Enroll fetches the CA pinned by its sha256, sends a CSR with the one-time token and writes
// node.key (0600), node.pem and ca.pem into Dir.
func Enroll(o EnrollOptions) (*x509.Certificate, error) {
	want := strings.ToLower(strings.TrimSpace(o.CASHA256))
	if len(want) != 64 {
		return nil, errors.New("enroll: --ca-sha256 must be 64 hex characters (printed by wafctl pki token)")
	}
	// 1. CA over TLS without verification, then pinned by fingerprint (nothing else is trusted yet)
	insecure := &http.Client{Timeout: Timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	r, err := insecure.Get("https://" + o.Central + "/ca")
	if err != nil {
		return nil, fmt.Errorf("enroll: GET /ca: %w", err)
	}
	caPEM, err := readOK(r)
	if err != nil {
		return nil, fmt.Errorf("enroll: GET /ca: %w", err)
	}
	ca, err := pki.ParseCertPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("enroll: CA: %w", err)
	}
	if got := pki.Fingerprint(ca); got != want {
		return nil, fmt.Errorf("enroll: CA fingerprint mismatch: got %s, want %s (wrong central or MITM): aborted", got, want)
	}
	// 2-4. key + CSR → POST /enroll, now verifying the server against the pinned CA
	key, csr, err := pki.NewCSR(o.CN)
	if err != nil {
		return nil, err
	}
	c := client(ca, nil)
	cert, gotCA, err := post(c, "https://"+o.Central+"/enroll", pki.EnrollRequest{Token: o.Token, CSR: string(csr)})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	if !bytes.Equal(bytes.TrimSpace(gotCA), bytes.TrimSpace(caPEM)) {
		return nil, errors.New("enroll: the central answered with a different CA")
	}
	return install(o.Dir, key, cert, caPEM, ca, o.CN)
}

func client(ca *x509.Certificate, certs []tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &http.Client{Timeout: Timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: certs, MinVersion: tls.VersionTLS12}}}
}

func post(c *http.Client, url string, body any) (cert, ca []byte, err error) {
	b, _ := json.Marshal(body)
	r, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	rb, err := readOK(r)
	if err != nil {
		return nil, nil, err
	}
	var resp pki.CertResponse
	if err := json.Unmarshal(rb, &resp); err != nil {
		return nil, nil, err
	}
	return []byte(resp.Cert), []byte(resp.CA), nil
}

func readOK(r *http.Response) ([]byte, error) {
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", r.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// install checks the cert (CA signature, CN, matching key) and swaps the files in atomically:
// every file is written as .new, then renamed.
func install(dir string, key, certPEM, caPEM []byte, ca *x509.Certificate, cn string) (*x509.Certificate, error) {
	cert, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if err := cert.CheckSignatureFrom(ca); err != nil || cert.Subject.CommonName != cn {
		return nil, fmt.Errorf("received certificate not valid for %s (signature: %v)", cn, err)
	}
	if _, err := tls.X509KeyPair(certPEM, key); err != nil {
		return nil, fmt.Errorf("received certificate does not match the key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	files := []struct {
		name string
		b    []byte
		mode os.FileMode
	}{{KeyFile, key, 0o600}, {CertFile, certPEM, 0o644}, {CAFile, caPEM, 0o644}}
	for _, f := range files {
		p := filepath.Join(dir, f.name+".new")
		if err := os.WriteFile(p, f.b, f.mode); err != nil {
			return nil, err
		}
		if err := os.Chmod(p, f.mode); err != nil {
			return nil, err
		}
	}
	for _, f := range files {
		if err := os.Rename(filepath.Join(dir, f.name+".new"), filepath.Join(dir, f.name)); err != nil {
			return nil, err
		}
	}
	return cert, nil
}
