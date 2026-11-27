package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
)

var cnRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Request describes a leaf to issue.
type Request struct {
	CN   string
	Kind string // client|server
	DNS  []string
	IPs  []net.IP
}

func (r Request) validate() error {
	if !cnRe.MatchString(r.CN) {
		return fmt.Errorf("pki: cn %q: want [A-Za-z0-9._-], 1-64 chars", r.CN)
	}
	switch r.Kind {
	case "client":
		if len(r.DNS) > 0 || len(r.IPs) > 0 {
			return errors.New("pki: --dns/--ip are for server certificates (a client cert has SAN DNS = cn)")
		}
	case "server":
	default:
		return fmt.Errorf("pki: kind %q: want client|server", r.Kind)
	}
	return nil
}

// Issued is a signed leaf.
type Issued struct {
	Cert  *x509.Certificate
	PEM   []byte // certificate
	Entry Entry
}

// Issue generates a key and signs a leaf for r. Returns the cert and the key PEM (PKCS#8).
func (s *Store) Issue(r Request) (*Issued, []byte, error) {
	if err := r.validate(); err != nil {
		return nil, nil, err
	}
	k, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	is, err := s.sign(r, k.Public())
	if err != nil {
		return nil, nil, err
	}
	kp, err := KeyPEM(k)
	return is, kp, err
}

// SignCSR verifies a CSR (signature, CN == wantCN, P-256 key) and signs a client leaf for it.
func (s *Store) SignCSR(csrPEM []byte, wantCN string) (*Issued, error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("pki: csr: no CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: csr signature: %w", err)
	}
	if csr.Subject.CommonName != wantCN {
		return nil, fmt.Errorf("pki: csr cn %q != %q", csr.Subject.CommonName, wantCN)
	}
	if !isP256(csr.PublicKey) {
		return nil, errors.New("pki: csr key must be ECDSA P-256")
	}
	r := Request{CN: wantCN, Kind: "client"}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return s.sign(r, csr.PublicKey.(crypto.PublicKey))
}

// sign creates the leaf for pub, writes issued/<serial>.pem and appends the index entry.
func (s *Store) sign(r Request, pub crypto.PublicKey) (*Issued, error) {
	var out *Issued
	err := s.locked(func() error {
		ca, key, err := s.CA()
		if err != nil {
			return err
		}
		serial, err := newSerial()
		if err != nil {
			return err
		}
		now := s.now()
		tpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: r.CN},
			NotBefore:             now.Add(-Backdate),
			NotAfter:              now.Add(LeafValidity),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		if r.Kind == "client" {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			tpl.DNSNames = []string{r.CN}
		} else {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tpl.DNSNames = r.DNS
			tpl.IPAddresses = r.IPs
		}
		if tpl.NotAfter.After(ca.NotAfter) {
			tpl.NotAfter = ca.NotAfter
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, pub, key)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		e := Entry{Serial: SerialHex(serial), CN: r.CN, Kind: r.Kind, NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC()}
		p := CertPEM(der)
		if err := writeAtomic(s.path("issued", e.Serial+".pem"), p, 0o644); err != nil {
			return err
		}
		ix, err := s.readIndex()
		if err != nil {
			return err
		}
		ix.Certs = append(ix.Certs, e)
		if err := s.writeIndex(ix); err != nil {
			return err
		}
		out = &Issued{Cert: cert, PEM: p, Entry: e}
		return nil
	})
	return out, err
}

func isP256(pub any) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	return ok && k.Curve == elliptic.P256()
}

// NewCSR generates a P-256 key and a CSR with CN = cn (node side of enroll/renew).
func NewCSR(cn string) (keyPEM, csrPEM []byte, err error) {
	k, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		return nil, nil, err
	}
	if keyPEM, err = KeyPEM(k); err != nil {
		return nil, nil, err
	}
	return keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
