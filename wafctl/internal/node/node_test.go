package node

import (
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginxawswaf/wafctl/internal/pki"
)

func central(t *testing.T) (*pki.Store, string) {
	t.Helper()
	s := &pki.Store{Dir: filepath.Join(t.TempDir(), "pki")}
	if err := s.Init("node"); err != nil {
		t.Fatal(err)
	}
	is, key, _ := s.Issue(pki.Request{CN: "ingress", Kind: "server", DNS: []string{"ingress"}, IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "s.pem"), is.PEM, 0o600)
	os.WriteFile(filepath.Join(d, "s.key"), key, 0o600)
	ca, _ := s.CACert()
	cfg, err := pki.TLSConfig(filepath.Join(d, "s.pem"), filepath.Join(d, "s.key"), ca)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer((&pki.Server{Store: s, Rate: 100}).Handler())
	ts.TLS = cfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return s, strings.TrimPrefix(ts.URL, "https://")
}

func TestND1_RenewSkipsWhenFresh(t *testing.T) {
	s, addr := central(t)
	dir := filepath.Join(t.TempDir(), "_node")
	tok, fp, _ := s.NewToken("lab-node-2", time.Hour)
	// a wrong pin aborts before anything is sent or written
	if _, err := Enroll(EnrollOptions{Central: addr, Token: tok, CASHA256: strings.Repeat("0", 64), CN: "lab-node-2", Dir: dir}); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("wrong pin: %v", err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("wrong pin wrote %s", dir)
	}
	c, err := Enroll(EnrollOptions{Central: addr, Token: tok, CASHA256: fp, CN: "lab-node-2", Dir: dir})
	if err != nil || c.Subject.CommonName != "lab-node-2" {
		t.Fatalf("enroll: %v", err)
	}
	if st, _ := os.Stat(filepath.Join(dir, KeyFile)); st.Mode().Perm() != 0o600 {
		t.Errorf("key mode %v", st.Mode())
	}
	// fresh cert (90 d): no renewal, no request
	if n, err := Renew(RenewOptions{Central: "127.0.0.1:1", Dir: dir}); n != nil || err != nil {
		t.Errorf("fresh renew: %v %v", n, err)
	}
	// 61 d later (29 d left): renews over mTLS
	later := func() time.Time { return time.Now().Add(61 * 24 * time.Hour) }
	n, err := Renew(RenewOptions{Central: addr, Dir: dir, Now: later})
	if err != nil || n == nil || n.SerialNumber.Cmp(c.SerialNumber) == 0 {
		t.Fatalf("expiring renew: %v", err)
	}
	e, _ := s.Lookup(pki.SerialHex(c.SerialNumber))
	if e.RenewedBy == nil || *e.RenewedBy != pki.SerialHex(n.SerialNumber) {
		t.Errorf("old entry %+v", e)
	}
	// --force renews again with the new cert
	if f, err := Renew(RenewOptions{Central: addr, Dir: dir, Force: true}); err != nil || f == nil {
		t.Errorf("force renew: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 3 {
		t.Errorf("leftover files: %v", ents)
	}
}
