package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Server is the enrollment API (`wafctl pki serve`): GET /ca, POST /enroll (token),
// POST /renew (client cert), GET /healthz. Rate limit: Rate requests per minute per IP.
type Server struct {
	Store *Store
	Rate  int         // requests/min per IP (0 → 10)
	Log   *log.Logger // nil → no log
	Now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// EnrollRequest / RenewRequest / CertResponse are the JSON bodies.
type EnrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}
type RenewRequest struct {
	CSR string `json:"csr"`
}
type CertResponse struct {
	Cert string `json:"cert"`
	CA   string `json:"ca"`
}

const maxBody = 64 << 10

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// allow is a per-IP token bucket: Rate tokens, refilled at Rate/min.
func (s *Server) allow(ip string) bool {
	rate := float64(s.Rate)
	if rate <= 0 {
		rate = 10
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buckets == nil {
		s.buckets = map[string]*bucket{}
	}
	now := s.now()
	b := s.buckets[ip]
	if b == nil {
		b = &bucket{tokens: rate, last: now}
		s.buckets[ip] = b
	}
	b.tokens += now.Sub(b.last).Minutes() * rate
	if b.tokens > rate {
		b.tokens = rate
	}
	b.last = now
	if len(s.buckets) > 10000 { // bound memory: drop full buckets
		for k, v := range s.buckets {
			if v.tokens >= rate && k != ip {
				delete(s.buckets, k)
			}
		}
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Handler returns the HTTP handler (TLS is set up by the caller, see TLSConfig).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /ca", func(w http.ResponseWriter, r *http.Request) {
		b, err := s.Store.CAPEM()
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(b)
	})
	mux.HandleFunc("POST /enroll", s.enroll)
	mux.HandleFunc("POST /renew", s.renew)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !s.allow(ip) {
			s.fail(w, r, http.StatusTooManyRequests, errors.New("rate limited"))
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	cn, err := csrCN([]byte(req.CSR))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	// the token is bound to a CN: a CSR for another CN is refused (and does not burn the token)
	if err := s.Store.UseToken(req.Token, cn); err != nil {
		s.fail(w, r, http.StatusForbidden, err)
		return
	}
	is, err := s.Store.SignCSR([]byte(req.CSR), cn)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	s.logf("enroll cn=%s serial=%s from %s", cn, is.Entry.Serial, r.RemoteAddr)
	s.reply(w, r, is)
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		s.fail(w, r, http.StatusUnauthorized, errors.New("client certificate required"))
		return
	}
	cur := r.TLS.VerifiedChains[0][0]
	if !hasEKU(cur, x509.ExtKeyUsageClientAuth) {
		s.fail(w, r, http.StatusForbidden, errors.New("not a client certificate"))
		return
	}
	serial := SerialHex(cur.SerialNumber)
	e, err := s.Store.Lookup(serial)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	if e == nil || e.CN != cur.Subject.CommonName || e.RevokedAt != nil || !s.now().Before(e.NotAfter) {
		s.fail(w, r, http.StatusForbidden, errors.New("certificate revoked, expired or unknown"))
		return
	}
	var req RenewRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	is, err := s.Store.SignCSR([]byte(req.CSR), cur.Subject.CommonName)
	if err != nil {
		s.fail(w, r, http.StatusForbidden, err)
		return
	}
	if err := s.Store.MarkRenewed(serial, is.Entry.Serial); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	s.logf("renew cn=%s serial=%s -> %s from %s", e.CN, serial, is.Entry.Serial, r.RemoteAddr)
	s.reply(w, r, is)
}

func (s *Server) reply(w http.ResponseWriter, r *http.Request, is *Issued) {
	ca, err := s.Store.CAPEM()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CertResponse{Cert: string(is.PEM), CA: string(ca)})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.logf("%s %s from %s: %d %v", r.Method, r.URL.Path, r.RemoteAddr, code, err)
	msg := http.StatusText(code)
	if code == http.StatusBadRequest {
		msg = err.Error() // malformed input only; auth failures stay generic
	}
	http.Error(w, msg, code)
}

func (s *Server) logf(f string, a ...any) {
	if s.Log != nil {
		s.Log.Printf(f, a...)
	}
}

func decode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// csrCN checks a CSR (PEM, signature, P-256) before any token is consumed; returns its CN.
func csrCN(p []byte) (string, error) {
	blk, _ := pem.Decode(p)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return "", errors.New("csr: no CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", errors.New("csr: bad signature")
	}
	if !isP256(csr.PublicKey) {
		return "", errors.New("csr: key must be ECDSA P-256")
	}
	if !cnRe.MatchString(csr.Subject.CommonName) {
		return "", errors.New("csr: invalid cn")
	}
	return csr.Subject.CommonName, nil
}

func hasEKU(c *x509.Certificate, u x509.ExtKeyUsage) bool {
	for _, x := range c.ExtKeyUsage {
		if x == u {
			return true
		}
	}
	return false
}

// TLSConfig: server cert (the ingress one) + optional client certs verified against the CA.
func TLSConfig(certFile, keyFile string, ca *x509.Certificate) (*tls.Config, error) {
	kp, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{Certificates: []tls.Certificate{kp}, ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
