package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// serveEnv: a real-clock store (TLS verification uses time.Now), a TLS test server and a CA pool.
func serveEnv(t *testing.T, rate int) (*Store, *Server, *httptest.Server, *x509.CertPool) {
	t.Helper()
	s := &Store{Dir: filepath.Join(t.TempDir(), "pki")}
	if err := s.Init("serve"); err != nil {
		t.Fatal(err)
	}
	is, key, err := s.Issue(Request{CN: "ingress", Kind: "server", DNS: []string{"ingress"}, IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "s.pem"), is.PEM, 0o600)
	os.WriteFile(filepath.Join(d, "s.key"), key, 0o600)
	ca, _ := s.CACert()
	cfg, err := TLSConfig(filepath.Join(d, "s.pem"), filepath.Join(d, "s.key"), ca)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Store: s, Rate: rate}
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = cfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return s, srv, ts, pool
}

func client(pool *x509.CertPool, certs ...tls.Certificate) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: certs}}}
}

func post(t *testing.T, c *http.Client, url string, body any) (int, CertResponse) {
	t.Helper()
	b, _ := json.Marshal(body)
	r, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var out CertResponse
	if r.StatusCode == 200 {
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	} else {
		io.Copy(io.Discard, r.Body)
	}
	return r.StatusCode, out
}

func enrollCert(t *testing.T, s *Store, c *http.Client, base, cn string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	tok, _, _ := s.NewToken(cn, time.Hour)
	key, csr, _ := NewCSR(cn)
	code, resp := post(t, c, base+"/enroll", EnrollRequest{Token: tok, CSR: string(csr)})
	if code != 200 {
		t.Fatalf("enroll %s: %d", cn, code)
	}
	kp, err := tls.X509KeyPair([]byte(resp.Cert), key)
	if err != nil {
		t.Fatal(err)
	}
	crt, _ := ParseCertPEM([]byte(resp.Cert))
	return kp, crt
}

func TestSRV1_EnrollValidToken(t *testing.T) {
	s, _, ts, pool := serveEnv(t, 100)
	c := client(pool)
	_, crt := enrollCert(t, s, c, ts.URL, "lab-node-2")
	ca, _ := s.CACert()
	if crt.Subject.CommonName != "lab-node-2" || crt.CheckSignatureFrom(ca) != nil || crt.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("cert cn %q eku %v", crt.Subject.CommonName, crt.ExtKeyUsage)
	}
	r, _ := c.Get(ts.URL + "/ca")
	b, _ := io.ReadAll(r.Body)
	pemCA, _ := s.CAPEM()
	if !bytes.Equal(b, pemCA) {
		t.Errorf("GET /ca differs")
	}
	// the token is single use
	tok, _, _ := s.NewToken("n3", time.Hour)
	_, csr, _ := NewCSR("n3")
	if code, _ := post(t, c, ts.URL+"/enroll", EnrollRequest{tok, string(csr)}); code != 200 {
		t.Fatalf("first use %d", code)
	}
	if code, _ := post(t, c, ts.URL+"/enroll", EnrollRequest{tok, string(csr)}); code != 403 {
		t.Errorf("reused token: %d, want 403", code)
	}
}

func TestSRV2_EnrollCNMismatch(t *testing.T) {
	s, _, ts, pool := serveEnv(t, 100)
	c := client(pool)
	tok, _, _ := s.NewToken("lab-node-2", time.Hour)
	_, csr, _ := NewCSR("other-node")
	if code, _ := post(t, c, ts.URL+"/enroll", EnrollRequest{tok, string(csr)}); code != 403 {
		t.Errorf("cn mismatch: %d, want 403", code)
	}
	if code, _ := post(t, c, ts.URL+"/enroll", EnrollRequest{"bogus", string(csr)}); code != 403 {
		t.Errorf("bad token: %d, want 403", code)
	}
	if code, _ := post(t, c, ts.URL+"/enroll", EnrollRequest{tok, "not a csr"}); code != 400 {
		t.Errorf("bad csr: %d, want 400", code)
	}
	// the mismatching attempt did not burn the token
	_, good, _ := NewCSR("lab-node-2")
	if code, _ := post(t, c, ts.URL+"/enroll", EnrollRequest{tok, string(good)}); code != 200 {
		t.Errorf("token after mismatch: %d, want 200", code)
	}
}

func TestSRV3_RenewAuth(t *testing.T) {
	s, _, ts, pool := serveEnv(t, 100)
	anon := client(pool)
	kp, old := enrollCert(t, s, anon, ts.URL, "lab-node-2")
	_, csr, _ := NewCSR("lab-node-2")
	if code, _ := post(t, anon, ts.URL+"/renew", RenewRequest{string(csr)}); code != 401 {
		t.Errorf("renew without client cert: %d, want 401", code)
	}
	mtls := client(pool, kp)
	_, other, _ := NewCSR("someone-else")
	if code, _ := post(t, mtls, ts.URL+"/renew", RenewRequest{string(other)}); code != 403 {
		t.Errorf("renew for another cn: %d, want 403", code)
	}
	code, resp := post(t, mtls, ts.URL+"/renew", RenewRequest{string(csr)})
	if code != 200 {
		t.Fatalf("renew: %d", code)
	}
	nw, _ := ParseCertPEM([]byte(resp.Cert))
	e, _ := s.Lookup(SerialHex(old.SerialNumber))
	if e.RenewedBy == nil || *e.RenewedBy != SerialHex(nw.SerialNumber) || e.RevokedAt != nil || e.Status(time.Now()) != "renewed" {
		t.Errorf("old entry after renew: %+v", e)
	}
	// revoked → 403 (the TLS handshake still accepts it: revocation is checked by the API)
	kp2, _ := enrollCert(t, s, anon, ts.URL, "n2")
	if _, err := s.Revoke("n2"); err != nil {
		t.Fatal(err)
	}
	_, csr2, _ := NewCSR("n2")
	if code, _ := post(t, client(pool, kp2), ts.URL+"/renew", RenewRequest{string(csr2)}); code != 403 {
		t.Errorf("renew with revoked cert: %d, want 403", code)
	}
}

func TestSRV4_RateLimit(t *testing.T) {
	_, srv, ts, pool := serveEnv(t, 10)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	srv.Now = func() time.Time { return now }
	c := client(pool)
	for i := 1; i <= 11; i++ {
		r, err := c.Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		want := 200
		if i == 11 {
			want = 429
		}
		if r.StatusCode != want {
			t.Errorf("request %d: %d, want %d", i, r.StatusCode, want)
		}
	}
	now = now.Add(6 * time.Second) // +1 token
	if r, _ := c.Get(ts.URL + "/healthz"); r.StatusCode != 200 {
		t.Errorf("after refill: %d", r.StatusCode)
	}
}
