package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// Crypto parameters (D26; fixed by the plan).
const (
	CAValidity   = 10 * 365 * 24 * time.Hour
	LeafValidity = 90 * 24 * time.Hour
	RenewBefore  = 30 * 24 * time.Hour
	CRLValidity  = 7 * 24 * time.Hour
	Backdate     = 5 * time.Minute
)

// ErrExists is returned by Init when ca.pem already exists.
var ErrExists = errors.New("pki: ca.pem already exists (refusing to overwrite the CA)")

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// newSerial is a random positive 128-bit serial.
func newSerial() (*big.Int, error) {
	for {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// SerialHex is the index/file form of a serial.
func SerialHex(n *big.Int) string { return fmt.Sprintf("%032x", n) }

// KeyPEM encodes k as PKCS#8 PEM.
func KeyPEM(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// CertPEM encodes DER as a CERTIFICATE PEM block.
func CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Init creates the CA (ca.pem, private/ca.key 0600 in a 0700 dir), an empty index and the first CRL.
func (s *Store) Init(name string) error {
	if name == "" {
		return errors.New("pki init: --name is required")
	}
	return s.locked(func() error {
		if _, err := os.Stat(s.path("ca.pem")); err == nil {
			return ErrExists
		}
		k, err := newKey()
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
			Subject:               pkix.Name{CommonName: "nginx-aws-waf CA " + name},
			NotBefore:             now.Add(-Backdate),
			NotAfter:              now.Add(CAValidity),
			IsCA:                  true,
			MaxPathLenZero:        true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			return err
		}
		kp, err := KeyPEM(k)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(s.path("private"), 0o700); err != nil {
			return err
		}
		if err := os.Chmod(s.path("private"), 0o700); err != nil {
			return err
		}
		if err := writeAtomic(s.path("private", "ca.key"), kp, 0o600); err != nil {
			return err
		}
		if err := os.MkdirAll(s.path("issued"), 0o755); err != nil {
			return err
		}
		if err := writeAtomic(s.path("ca.pem"), CertPEM(der), 0o644); err != nil {
			return err
		}
		ix := &Index{}
		if err := s.writeCRL(ix); err != nil {
			return err
		}
		return s.writeIndex(ix)
	})
}

// CA loads the CA certificate and key.
func (s *Store) CA() (*x509.Certificate, crypto.Signer, error) {
	cert, err := s.CACert()
	if err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(s.path("private", "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, nil, errors.New("pki: private/ca.key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	sg, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("pki: ca.key is not a signer")
	}
	return cert, sg, nil
}

// CACert loads ca.pem.
func (s *Store) CACert() (*x509.Certificate, error) {
	b, err := os.ReadFile(s.path("ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("pki: %w (run wafctl pki init)", err)
	}
	return ParseCertPEM(b)
}

// CAPEM returns ca.pem.
func (s *Store) CAPEM() ([]byte, error) { return os.ReadFile(s.path("ca.pem")) }

// ParseCertPEM parses the first CERTIFICATE block.
func ParseCertPEM(b []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, errors.New("pki: no CERTIFICATE PEM block")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

// Fingerprint is the hex sha256 of a certificate's DER (enrollment CA pinning).
func Fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}
