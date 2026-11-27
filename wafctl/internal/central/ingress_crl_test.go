package central

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginxawswaf/wafctl/internal/pki"
)

// V001-F1: a CRL from a store whose CA is not the ingress CA must never reach the ingress.
func TestCRL1_PublishRefusesForeignCA(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	a := &pki.Store{Dir: filepath.Join(t.TempDir(), "a"), Now: clock}
	b := &pki.Store{Dir: filepath.Join(t.TempDir(), "b"), Now: clock}
	for _, s := range []*pki.Store{a, b} {
		if err := s.Init("t-" + filepath.Base(s.Dir)); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	if _, err := RenderIngress(Defaults(), a, out, now); err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(IngressCertsDir(out), "crl.pem")
	before, _ := os.ReadFile(crlPath)

	if _, _, err := b.Issue(pki.Request{CN: "node-b", Kind: "client"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Revoke("node-b"); err != nil {
		t.Fatal(err)
	}
	ch, err := PublishCRL(b, out)
	if err == nil || !strings.Contains(err.Error(), "not the ingress CA") || ch {
		t.Fatalf("foreign CRL: changed=%v err=%v", ch, err)
	}
	if after, _ := os.ReadFile(crlPath); !bytes.Equal(before, after) {
		t.Fatalf("foreign CRL overwrote the ingress crl.pem")
	}

	if _, _, err := a.Issue(pki.Request{CN: "node-a", Kind: "client"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := a.Revoke("node-a"); err != nil {
		t.Fatal(err)
	}
	if ch, err := PublishCRL(a, out); err != nil || !ch {
		t.Fatalf("own CRL: changed=%v err=%v", ch, err)
	}
	ownCRL, _ := os.ReadFile(filepath.Join(a.Dir, "crl.pem"))
	if after, _ := os.ReadFile(crlPath); !bytes.Equal(ownCRL, after) {
		t.Fatalf("own CRL not published")
	}
}
