package pki

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Token is one enrollment token in tokens.json (only its sha256 is stored).
type Token struct {
	SHA256  string     `json:"sha256"`
	CN      string     `json:"cn"`
	Expires time.Time  `json:"expires"`
	UsedAt  *time.Time `json:"used_at"`
}

// ErrToken is returned for an unknown, used, expired or wrong-CN token (no detail for the caller).
var ErrToken = errors.New("pki: invalid, used or expired token")

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (s *Store) readTokens() ([]Token, error) {
	b, err := os.ReadFile(s.path("tokens.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ts []Token
	return ts, json.Unmarshal(b, &ts)
}

func (s *Store) writeTokens(ts []Token) error {
	if ts == nil {
		ts = []Token{}
	}
	b, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path("tokens.json"), append(b, '\n'), 0o600)
}

// NewToken creates a single-use enrollment token for cn valid for ttl. Returns the token (32 random
// bytes, base64url) and the CA fingerprint the node pins.
func (s *Store) NewToken(cn string, ttl time.Duration) (token, caSHA256 string, err error) {
	if !cnRe.MatchString(cn) {
		return "", "", fmt.Errorf("pki: cn %q: want [A-Za-z0-9._-], 1-64 chars", cn)
	}
	if ttl <= 0 || ttl > 30*24*time.Hour {
		return "", "", errors.New("pki: --ttl must be > 0 and <= 720h")
	}
	ca, err := s.CACert()
	if err != nil {
		return "", "", err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	err = s.locked(func() error {
		ts, err := s.readTokens()
		if err != nil {
			return err
		}
		now := s.now()
		kept := ts[:0]
		for _, t := range ts { // drop tokens expired for more than a week
			if t.Expires.After(now.Add(-7 * 24 * time.Hour)) {
				kept = append(kept, t)
			}
		}
		kept = append(kept, Token{SHA256: tokenHash(token), CN: cn, Expires: now.Add(ttl)})
		return s.writeTokens(kept)
	})
	return token, Fingerprint(ca), err
}

// UseToken consumes token for cn: it must exist, be unused, unexpired and bound to cn.
func (s *Store) UseToken(token, cn string) error {
	h := tokenHash(token)
	return s.locked(func() error {
		ts, err := s.readTokens()
		if err != nil {
			return err
		}
		now := s.now()
		for i := range ts {
			t := &ts[i]
			if subtle.ConstantTimeCompare([]byte(t.SHA256), []byte(h)) != 1 {
				continue
			}
			if t.UsedAt != nil || !now.Before(t.Expires) || t.CN != cn {
				return ErrToken
			}
			u := now
			t.UsedAt = &u
			return s.writeTokens(ts)
		}
		return ErrToken
	})
}
