package testrun

import (
	"os"
	"strings"
	"testing"
)

func TestT1_CorpusRejectsUnknownKeys(t *testing.T) {
	bad := "version: 1\ncases:\n  - id: a\n    site: demo\n    reqest: {path: /}\n    expect: {status: 200, terminating_rule: Default_Action}\n"
	if _, err := ParseCorpus([]byte(bad), "bad.yaml"); err == nil || !strings.Contains(err.Error(), "reqest") {
		t.Fatalf("unknown key accepted: %v", err)
	}
	good := strings.Replace(bad, "reqest", "request", 1)
	cs, err := ParseCorpus([]byte(good), "good.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cs[0].Request.Method != "GET" || cs[0].Request.XFF != "198.51.100.10" {
		t.Errorf("defaults not applied: %+v", cs[0].Request)
	}
	if _, err := LoadSuite("../../../tests/corpus"); err != nil {
		t.Errorf("repo corpus: %v", err)
	}
}

func TestT2_AuditLineParse(t *testing.T) {
	b, err := os.ReadFile("testdata/audit-line.json")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := ParseAuditLine(b, "x-waf-test")
	if !ok || !strings.HasSuffix(r.TestID, "-first-wins") {
		t.Fatalf("test id not found: %+v", r)
	}
	if r.Status != 403 || r.Summary["site"] != "demo" || r.Summary["mode"] != "enforce" || r.Term != 1200010 {
		t.Errorf("summary = %+v term=%d status=%d", r.Summary, r.Term, r.Status)
	}
	has := map[int]bool{}
	for _, id := range r.Matched {
		has[id] = true
	}
	if !has[1200010] || !has[1300050] {
		t.Errorf("matched = %v", r.Matched)
	}
	if TermName(r.Term, map[int]IndexEntry{1200010: {Name: "NoUserAgent_HEADER"}}) != "NoUserAgent_HEADER" || TermName(0, nil) != "Default_Action" {
		t.Error("TermName")
	}
	if _, ok := ParseAuditLine([]byte(`{"transaction":{"request":{"headers":{}}}}`), Header); ok {
		t.Error("line without test header accepted")
	}
}

func TestT3_BodyRepeatLength(t *testing.T) {
	r := &Request{BodyRepeat: &Repeat{Char: "x", Count: 12000, Prefix: "a=", Suffix: "<script>alert(1)</script>"}}
	b, ct := BuildBody(r)
	if len(b) != 2+12000+25 || !strings.HasPrefix(string(b), "a=xx") || !strings.HasSuffix(string(b), "</script>") {
		t.Errorf("len %d", len(b))
	}
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("ct %q", ct)
	}
	if b, _ := BuildBody(&Request{BodyRepeat: &Repeat{Count: 9000}}); len(b) != 9000 {
		t.Errorf("default char len %d", len(b))
	}
}
