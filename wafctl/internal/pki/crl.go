package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// Revoke marks the certificate with serial (hex) — or every non-revoked certificate of CN — as
// revoked and regenerates the CRL. Returns the revoked serials.
func (s *Store) Revoke(serialOrCN string) ([]string, error) {
	var done []string
	err := s.locked(func() error {
		ix, err := s.readIndex()
		if err != nil {
			return err
		}
		now := s.now()
		key := strings.ToLower(strings.TrimPrefix(serialOrCN, "0x"))
		for i := range ix.Certs {
			e := &ix.Certs[i]
			if e.Serial != key && e.CN != serialOrCN {
				continue
			}
			if e.RevokedAt != nil {
				continue
			}
			t := now
			e.RevokedAt = &t
			done = append(done, e.Serial)
		}
		if len(done) == 0 {
			return fmt.Errorf("pki: no valid certificate with serial or cn %q", serialOrCN)
		}
		if err := s.writeCRL(ix); err != nil {
			return err
		}
		return s.writeIndex(ix)
	})
	return done, err
}

// CRL regenerates crl.pem (this_update now, next_update now+7d, number+1).
func (s *Store) CRL() error {
	return s.locked(func() error {
		ix, err := s.readIndex()
		if err != nil {
			return err
		}
		if err := s.writeCRL(ix); err != nil {
			return err
		}
		return s.writeIndex(ix)
	})
}

// writeCRL signs a CRL of the revoked, not yet expired entries. Caller holds the lock and writes ix.
func (s *Store) writeCRL(ix *Index) error {
	ca, key, err := s.CA()
	if err != nil {
		return err
	}
	now := s.now()
	var revoked []x509.RevocationListEntry
	for _, e := range ix.Certs {
		if e.RevokedAt == nil {
			continue
		}
		n, ok := new(big.Int).SetString(e.Serial, 16)
		if !ok {
			return fmt.Errorf("pki: index: bad serial %q", e.Serial)
		}
		revoked = append(revoked, x509.RevocationListEntry{SerialNumber: n, RevocationTime: *e.RevokedAt})
	}
	ix.CRLNumber++
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(ix.CRLNumber),
		ThisUpdate:                now,
		NextUpdate:                now.Add(CRLValidity),
		RevokedCertificateEntries: revoked,
	}, ca, key)
	if err != nil {
		return err
	}
	return writeAtomic(s.path("crl.pem"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o644)
}

// ReadCRL parses crl.pem.
func (s *Store) ReadCRL() (*x509.RevocationList, error) {
	b, err := os.ReadFile(s.path("crl.pem"))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("pki: crl.pem: no PEM block")
	}
	return x509.ParseRevocationList(blk.Bytes)
}

// IsRevoked reports whether serial (hex) is revoked in the index.
func (s *Store) IsRevoked(serial string) (bool, error) {
	es, err := s.List()
	if err != nil {
		return false, err
	}
	for _, e := range es {
		if e.Serial == serial {
			return e.RevokedAt != nil, nil
		}
	}
	return false, nil
}
