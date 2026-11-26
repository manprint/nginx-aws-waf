package testrun

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
)

// IndexEntry mirrors runtime/<rev>/rules-index.json values.
type IndexEntry struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	Label string `json:"label"`
	Site  string `json:"site"`
}

// LoadIndex reads rules-index.json.
func LoadIndex(path string) (map[int]IndexEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := map[string]IndexEntry{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	m := map[int]IndexEntry{}
	for k, v := range raw {
		id, err := strconv.Atoi(k)
		if err == nil {
			m[id] = v
		}
	}
	return m, nil
}

// Record is the WAF outcome of one audited transaction.
type Record struct {
	TestID  string
	Status  int
	Summary map[string]string // site, mode, term, ta, aws, da, fail
	Raw     string
	Term    int
	Matched []int // base ids in order of first appearance
}

type auditLine struct {
	Transaction struct {
		Request struct {
			Headers map[string]any `json:"headers"`
		} `json:"request"`
		Response struct {
			HTTPCode int `json:"http_code"`
		} `json:"response"`
		Messages []struct {
			Message string `json:"message"`
			Details struct {
				RuleID string `json:"ruleId"`
				Data   string `json:"data"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
}

// ParseSummary splits "k=v;k=v".
func ParseSummary(s string) map[string]string {
	m := map[string]string{}
	for _, kv := range strings.Split(s, ";") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// ParseAuditLine decodes one JSON audit line; ok=false when it has no X-Waf-Test header.
func ParseAuditLine(line []byte, header string) (Record, bool) {
	var a auditLine
	if err := json.Unmarshal(line, &a); err != nil {
		return Record{}, false
	}
	r := Record{Status: a.Transaction.Response.HTTPCode}
	for k, v := range a.Transaction.Request.Headers {
		if strings.EqualFold(k, header) {
			if s, ok := v.(string); ok {
				r.TestID = s
			}
		}
	}
	if r.TestID == "" {
		return r, false
	}
	seen := map[int]bool{}
	for _, m := range a.Transaction.Messages {
		switch {
		case m.Message == "AWSWAF_SUMMARY":
			r.Summary = ParseSummary(m.Details.Data)
			r.Raw = m.Details.Data
			r.Term, _ = strconv.Atoi(r.Summary["term"])
		case strings.HasPrefix(m.Message, "AWSWAF 1"):
			id, err := strconv.Atoi(strings.TrimPrefix(m.Message, "AWSWAF "))
			if err != nil {
				continue
			}
			base := id / 10 * 10
			if !seen[base] {
				seen[base] = true
				r.Matched = append(r.Matched, base)
			}
		}
	}
	return r, true
}

// ReadAudit reads audit records from offset; lines up to 8 MiB.
func ReadAudit(path string, offset int64, header string) (map[string]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	out := map[string]Record{}
	rd := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := readLine(rd, 8<<20)
		if len(line) > 0 {
			if r, ok := ParseAuditLine(line, header); ok {
				out[r.TestID] = r
			}
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func readLine(rd *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := rd.ReadLine()
		if len(buf)+len(chunk) <= max {
			buf = append(buf, chunk...)
		}
		if err != nil || !isPrefix {
			return buf, err
		}
	}
}
