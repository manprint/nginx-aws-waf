package testrun

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Header carries the per-request test id.
const Header = "X-Waf-Test"

// Runner sends cases and checks the audit log.
type Runner struct {
	Target    string            // e.g. http://127.0.0.1:8080
	AuditPath string            // node audit log
	IndexPath string            // runtime/current/rules-index.json
	ListsDir  string            // for xff "@list:NAME"
	Hosts     map[string]string // site id → Host header
	Wait      time.Duration
	client    *http.Client
}

// Result is the outcome of one case.
type Result struct {
	ID      string   `json:"id"`
	OK      bool     `json:"ok"`
	Status  int      `json:"status"`
	Term    string   `json:"term"`
	Mode    string   `json:"mode"`
	Matches []string `json:"matches"`
	Summary string   `json:"summary,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func (r *Runner) resolveXFF(x string) (string, error) {
	name, ok := strings.CutPrefix(x, "@list:")
	if !ok {
		return x, nil
	}
	f, err := os.Open(filepath.Join(r.ListsDir, name))
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		ip, _, _ := strings.Cut(l, "/")
		return ip, nil
	}
	return "", fmt.Errorf("list %s has no entries", name)
}

// Send performs one case request and returns the HTTP status.
func (r *Runner) Send(c *Case, testID string) (int, error) {
	if r.client == nil {
		r.client = &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	tu, err := url.Parse(r.Target)
	if err != nil {
		return 0, err
	}
	body, ct := BuildBody(&c.Request)
	var rdr io.Reader = bytes.NewReader(body)
	if c.Request.Chunked {
		rdr = io.MultiReader(bytes.NewReader(body)) // unknown length → chunked
	}
	req, err := http.NewRequest(c.Request.Method, r.Target, rdr)
	if err != nil {
		return 0, err
	}
	req.URL = &url.URL{Scheme: tu.Scheme, Host: tu.Host, Opaque: c.Request.Path}
	if c.Request.Chunked {
		req.ContentLength = -1
	} else {
		req.ContentLength = int64(len(body))
		if len(body) == 0 {
			req.Body = http.NoBody
		}
	}
	host := c.Request.Host
	if host == "" {
		host = r.Hosts[c.Site]
		if host == "" {
			return 0, fmt.Errorf("unknown site %q", c.Site)
		}
	}
	req.Host = host
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) wafctl-test/1")
	req.Header.Set("Accept", "*/*")
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	xff, err := r.resolveXFF(c.Request.XFF)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Forwarded-For", xff)
	for k, v := range c.Request.Headers {
		if v == "" {
			if strings.EqualFold(k, "User-Agent") {
				req.Header["User-Agent"] = []string{""} // Go omits an empty UA
			} else {
				req.Header.Del(k)
			}
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set(Header, testID)
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

func runID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run executes the cases and returns one result per case.
func (r *Runner) Run(cases []Case) ([]Result, error) {
	idx, err := LoadIndex(r.IndexPath)
	if err != nil {
		return nil, err
	}
	var off int64
	if st, err := os.Stat(r.AuditPath); err == nil {
		off = st.Size()
	}
	rid := runID()
	statuses := make([]int, len(cases))
	errs := make([]error, len(cases))
	for i := range cases {
		statuses[i], errs[i] = r.Send(&cases[i], rid+"-"+cases[i].ID)
	}
	w := r.Wait
	if w == 0 {
		w = time.Second
	}
	time.Sleep(w)
	recs, err := ReadAudit(r.AuditPath, off, Header)
	if err != nil {
		return nil, err
	}
	res := make([]Result, len(cases))
	for i, c := range cases {
		res[i] = evaluate(&c, statuses[i], errs[i], recs[rid+"-"+c.ID], idx)
	}
	return res, nil
}

// TermName maps a terminating id to its rule name.
func TermName(term int, idx map[int]IndexEntry) string {
	if term == 0 {
		return "Default_Action"
	}
	if e, ok := idx[term/10*10]; ok {
		return e.Name
	}
	return fmt.Sprint(term)
}

func evaluate(c *Case, status int, sendErr error, rec Record, idx map[int]IndexEntry) Result {
	r := Result{ID: c.ID, Status: status}
	if sendErr != nil {
		r.Error = sendErr.Error()
		return r
	}
	if rec.Summary == nil {
		r.Error = "no audit record with AWSWAF_SUMMARY"
		return r
	}
	r.Term = TermName(rec.Term, idx)
	r.Mode = rec.Summary["mode"]
	r.Summary = rec.Raw
	for _, id := range rec.Matched {
		if e, ok := idx[id]; ok {
			r.Matches = append(r.Matches, e.Name)
		}
	}
	var why []string
	if status != c.Expect.Status {
		why = append(why, fmt.Sprintf("status %d != %d", status, c.Expect.Status))
	}
	if r.Term != c.Expect.TerminatingRule {
		why = append(why, fmt.Sprintf("term %s != %s", r.Term, c.Expect.TerminatingRule))
	}
	have := map[string]bool{}
	for _, m := range r.Matches {
		have[m] = true
	}
	for _, m := range c.Expect.Matches {
		if !have[m] {
			why = append(why, "missing match "+m)
		}
	}
	r.Error = strings.Join(why, "; ")
	r.OK = r.Error == ""
	return r
}

// Print writes results as text or json; returns the number of failures.
func Print(w io.Writer, res []Result, format string) int {
	fails := 0
	for _, r := range res {
		if !r.OK {
			fails++
		}
	}
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"results": res, "passed": len(res) - fails, "total": len(res)})
		return fails
	}
	for _, r := range res {
		tag := "OK"
		if !r.OK {
			tag = "FAIL"
		}
		fmt.Fprintf(w, "%s %s status=%d term=%s matches=%s", tag, r.ID, r.Status, r.Term, strings.Join(r.Matches, ","))
		if !r.OK {
			fmt.Fprintf(w, " (%s)", r.Error)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "PASSED %d/%d\n", len(res)-fails, len(res))
	return fails
}
