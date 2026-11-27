// Package pki is the small CA of the WAF fleet (D26): ECDSA P-256, CA 10 y, leaves 90 d, CRL 7 d,
// single-use enrollment tokens. stdlib crypto only. The CA key never leaves $WAF_PKI_DIR/private.
package pki

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Entry is one issued leaf certificate in index.json.
type Entry struct {
	Serial    string     `json:"serial"` // lower-case hex
	CN        string     `json:"cn"`
	Kind      string     `json:"kind"` // client|server
	NotBefore time.Time  `json:"not_before"`
	NotAfter  time.Time  `json:"not_after"`
	RevokedAt *time.Time `json:"revoked_at"`
	RenewedBy *string    `json:"renewed_by"`
}

// Index is index.json: the issued certificates and the last CRL number.
type Index struct {
	CRLNumber int64   `json:"crl_number"`
	Certs     []Entry `json:"certs"`
}

// Status of e at now: revoked, expired, renewed (replaced, still valid until it expires),
// expiring (< RenewBefore left) or valid.
func (e Entry) Status(now time.Time) string {
	switch {
	case e.RevokedAt != nil:
		return "revoked"
	case !now.Before(e.NotAfter):
		return "expired"
	case e.RenewedBy != nil:
		return "renewed"
	case e.NotAfter.Sub(now) < RenewBefore:
		return "expiring"
	}
	return "valid"
}

// Store is a PKI directory.
type Store struct {
	Dir string
	Now func() time.Time // injectable clock (tests); nil → time.Now
}

// Open returns the store at dir.
func Open(dir string) *Store { return &Store{Dir: dir} }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Store) path(p ...string) string { return filepath.Join(append([]string{s.Dir}, p...)...) }

// locked runs fn under an exclusive flock on index.json.lock.
func (s *Store) locked(fn func() error) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path("index.json.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock %s: %w", f.Name(), err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

// readIndex loads index.json (missing → empty).
func (s *Store) readIndex() (*Index, error) {
	b, err := os.ReadFile(s.path("index.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &Index{}, nil
	}
	if err != nil {
		return nil, err
	}
	var ix Index
	if err := json.Unmarshal(b, &ix); err != nil {
		return nil, fmt.Errorf("index.json: %w", err)
	}
	return &ix, nil
}

func (s *Store) writeIndex(ix *Index) error {
	if ix.Certs == nil {
		ix.Certs = []Entry{}
	}
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path("index.json"), append(b, '\n'), 0o600)
}

// List returns the index entries (under the lock).
func (s *Store) List() ([]Entry, error) {
	var out []Entry
	err := s.locked(func() error {
		ix, err := s.readIndex()
		if err == nil {
			out = ix.Certs
		}
		return err
	})
	return out, err
}

// Lookup returns the index entry of serial (nil when unknown).
func (s *Store) Lookup(serial string) (*Entry, error) {
	var out *Entry
	err := s.locked(func() error {
		ix, err := s.readIndex()
		if err != nil {
			return err
		}
		for i := range ix.Certs {
			if ix.Certs[i].Serial == serial {
				e := ix.Certs[i]
				out = &e
			}
		}
		return nil
	})
	return out, err
}

// MarkRenewed records that oldSerial was replaced by newSerial (it is not revoked).
func (s *Store) MarkRenewed(oldSerial, newSerial string) error {
	return s.locked(func() error {
		ix, err := s.readIndex()
		if err != nil {
			return err
		}
		for i := range ix.Certs {
			if ix.Certs[i].Serial == oldSerial {
				n := newSerial
				ix.Certs[i].RenewedBy = &n
				return s.writeIndex(ix)
			}
		}
		return fmt.Errorf("pki: unknown serial %s", oldSerial)
	})
}

// writeAtomic writes path via a temp file + rename with the given mode.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
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
