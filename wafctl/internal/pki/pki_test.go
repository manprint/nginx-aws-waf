package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	s := &Store{Dir: filepath.Join(t.TempDir(), "pki"), Now: func() time.Time { return now }}
	if err := s.Init("test"); err != nil {
		t.Fatal(err)
	}
	return s, &now
}

func TestPKI1_InitCA(t *testing.T) {
	s, _ := newStore(t)
	ca, err := s.CACert()
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || !ca.MaxPathLenZero || ca.Subject.CommonName != "nginx-aws-waf CA test" {
		t.Errorf("ca %v %v %q", ca.IsCA, ca.MaxPathLenZero, ca.Subject.CommonName)
	}
	if ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage %v", ca.KeyUsage)
	}
	if k, ok := ca.PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		t.Errorf("ca key not P-256")
	}
	if d := ca.NotAfter.Sub(ca.NotBefore); d < CAValidity || d > CAValidity+time.Hour {
		t.Errorf("ca validity %v", d)
	}
	for p, want := range map[string]os.FileMode{"private/ca.key": 0o600, "private": 0o700 | os.ModeDir} {
		st, err := os.Stat(filepath.Join(s.Dir, p))
		if err != nil || st.Mode() != want {
			t.Errorf("%s mode %v want %v (%v)", p, st.Mode(), want, err)
		}
	}
	if _, _, err := s.CA(); err != nil {
		t.Errorf("ca key: %v", err)
	}
	if crl, err := s.ReadCRL(); err != nil || crl.Number.Int64() != 1 {
		t.Errorf("initial crl %v", err)
	}
}

func verify(t *testing.T, s *Store, c *x509.Certificate, eku x509.ExtKeyUsage, at time.Time) error {
	t.Helper()
	ca, _ := s.CACert()
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{eku}, CurrentTime: at})
	return err
}

func TestPKI2_ClientCertEKU(t *testing.T) {
	s, now := newStore(t)
	is, key, err := s.Issue(Request{CN: "lab-node-2", Kind: "client"})
	if err != nil {
		t.Fatal(err)
	}
	c := is.Cert
	if err := verify(t, s, c, x509.ExtKeyUsageClientAuth, *now); err != nil {
		t.Errorf("client auth: %v", err)
	}
	if err := verify(t, s, c, x509.ExtKeyUsageServerAuth, *now); err == nil {
		t.Errorf("client cert verified for ServerAuth")
	}
	if c.Subject.CommonName != "lab-node-2" || len(c.DNSNames) != 1 || c.DNSNames[0] != "lab-node-2" || c.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("leaf %q %v %v", c.Subject.CommonName, c.DNSNames, c.KeyUsage)
	}
	if !c.NotBefore.Equal(now.Add(-Backdate)) || !c.NotAfter.Equal(now.Add(LeafValidity)) {
		t.Errorf("validity %v..%v", c.NotBefore, c.NotAfter)
	}
	if c.SerialNumber.BitLen() < 64 { // 128-bit random: < 2^-64 chance to fail
		t.Errorf("serial too short: %v", c.SerialNumber)
	}
	if blk, _ := pem.Decode(key); blk == nil || blk.Type != "PRIVATE KEY" {
		t.Errorf("key pem")
	}
	srv, _, err := s.Issue(Request{CN: "ingress", Kind: "server", DNS: []string{"ingress", "central.lab.test"}})
	if err != nil || verify(t, s, srv.Cert, x509.ExtKeyUsageServerAuth, *now) != nil || srv.Cert.VerifyHostname("central.lab.test") != nil {
		t.Errorf("server cert: %v", err)
	}
	if _, _, err := s.Issue(Request{CN: "x", Kind: "client", DNS: []string{"y"}}); err == nil {
		t.Errorf("client with --dns accepted")
	}
	if _, _, err := s.Issue(Request{CN: "../x", Kind: "client"}); err == nil {
		t.Errorf("bad cn accepted")
	}
	es, _ := s.List()
	if len(es) != 2 || es[0].Status(*now) != "valid" || es[0].Status(now.Add(61*24*time.Hour)) != "expiring" || es[0].Status(now.Add(91*24*time.Hour)) != "expired" {
		t.Errorf("list %+v", es)
	}
	// CSR path (enroll/renew): CN must match, key P-256
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "lab-node-3"}}, k)
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := s.SignCSR(csr, "lab-node-9"); err == nil {
		t.Errorf("csr cn mismatch accepted")
	}
	if is, err := s.SignCSR(csr, "lab-node-3"); err != nil || verify(t, s, is.Cert, x509.ExtKeyUsageClientAuth, *now) != nil {
		t.Errorf("csr sign: %v", err)
	}
}

func TestPKI3_RevokeCRL(t *testing.T) {
	s, now := newStore(t)
	a, _, _ := s.Issue(Request{CN: "n1", Kind: "client"})
	b, _, _ := s.Issue(Request{CN: "n2", Kind: "client"})
	before, _ := s.ReadCRL()
	got, err := s.Revoke("n1")
	if err != nil || len(got) != 1 || got[0] != a.Entry.Serial {
		t.Fatalf("revoke %v %v", got, err)
	}
	crl, err := s.ReadCRL()
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := s.CACert()
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Errorf("crl signature: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(a.Cert.SerialNumber) != 0 {
		t.Errorf("crl entries %v", crl.RevokedCertificateEntries)
	}
	if crl.Number.Cmp(new(big.Int).Add(before.Number, big.NewInt(1))) != 0 {
		t.Errorf("crl number %v after %v", crl.Number, before.Number)
	}
	if !crl.NextUpdate.Equal(now.Add(CRLValidity)) || !crl.ThisUpdate.Equal(*now) {
		t.Errorf("crl window %v..%v", crl.ThisUpdate, crl.NextUpdate)
	}
	if _, err := s.Revoke("n1"); err == nil {
		t.Errorf("revoking twice succeeded")
	}
	if got, err := s.Revoke(b.Entry.Serial); err != nil || got[0] != b.Entry.Serial {
		t.Errorf("revoke by serial %v %v", got, err)
	}
	if r, _ := s.IsRevoked(b.Entry.Serial); !r {
		t.Errorf("IsRevoked false")
	}
	if err := s.CRL(); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.ReadCRL(); c.Number.Int64() != crl.Number.Int64()+2 || len(c.RevokedCertificateEntries) != 2 {
		t.Errorf("crl regen number %v entries %d", c.Number, len(c.RevokedCertificateEntries))
	}
}

func TestPKI4_TokenSingleUseAndExpiry(t *testing.T) {
	s, now := newStore(t)
	tok, fp, err := s.NewToken("lab-node-2", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := s.CACert()
	if fp != Fingerprint(ca) || len(fp) != 64 || len(tok) != 43 {
		t.Errorf("fp %s tok %s", fp, tok)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, "tokens.json"))
	if st, _ := os.Stat(filepath.Join(s.Dir, "tokens.json")); st.Mode() != 0o600 {
		t.Errorf("tokens.json mode %v", st.Mode())
	}
	if string(b) == "" || contains(b, tok) {
		t.Errorf("token stored in clear")
	}
	if err := s.UseToken(tok, "other"); !errors.Is(err, ErrToken) {
		t.Errorf("wrong cn: %v", err)
	}
	if err := s.UseToken(tok, "lab-node-2"); err != nil {
		t.Errorf("first use: %v", err)
	}
	if err := s.UseToken(tok, "lab-node-2"); !errors.Is(err, ErrToken) {
		t.Errorf("second use: %v", err)
	}
	tok2, _, _ := s.NewToken("lab-node-2", time.Hour)
	*now = now.Add(time.Hour)
	if err := s.UseToken(tok2, "lab-node-2"); !errors.Is(err, ErrToken) {
		t.Errorf("expired token: %v", err)
	}
	if err := s.UseToken("nope", "lab-node-2"); !errors.Is(err, ErrToken) {
		t.Errorf("unknown token: %v", err)
	}
}

func contains(b []byte, s string) bool { return strings.Contains(string(b), s) }

func TestPKI5_InitTwice(t *testing.T) {
	s, _ := newStore(t)
	before, _ := s.CAPEM()
	if err := s.Init("again"); !errors.Is(err, ErrExists) {
		t.Errorf("second init: %v", err)
	}
	after, _ := s.CAPEM()
	if string(before) != string(after) {
		t.Errorf("ca.pem changed")
	}
}
