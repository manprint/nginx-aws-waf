package stats

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

var t0 = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

func TestS1_SourceByWindow(t *testing.T) {
	for _, c := range []struct {
		by   string
		win  time.Duration
		src  string
		from string
	}{
		{"overview", 59 * time.Minute, "events", "FROM waf.events"},
		{"overview", time.Hour, "agg", "FROM waf.agg_requests_1m"},
		{"site", 24 * time.Hour, "agg", "FROM waf.agg_requests_1m"},
		{"rule", 15 * time.Minute, "events", "FROM waf.matches"},
		{"rule", 2 * time.Hour, "agg", "FROM waf.agg_matches_1m"},
		{"path", 48 * time.Hour, "events", "FROM waf.events"},
	} {
		v, err := Select(Options{From: t0.Add(-c.win), To: t0, By: c.by, Top: 20})
		if err != nil || v.Source != c.src || !strings.Contains(v.SQL, c.from) {
			t.Errorf("%s %v: source %s sql %q err %v", c.by, c.win, v.Source, v.SQL, err)
		}
	}
	if _, err := Select(Options{By: "nope"}); err == nil {
		t.Error("unknown view accepted")
	}
	p := Params(Options{From: t0.Add(-time.Hour), To: t0, Sites: []string{"a'b"}, Top: 5})
	if p["site"] != `['a\'b']` || p["top"] != "5" || p["from_ms"] != "1795770000000" {
		t.Errorf("params %v", p)
	}
	for _, v := range Views {
		s, _ := Select(Options{From: t0.Add(-time.Minute), To: t0, By: v})
		if !strings.Contains(s.SQL, "(empty({site:Array(String)}) OR site_id IN {site:Array(String)})") {
			t.Errorf("%s: no site filter", v)
		}
	}
}

func TestS2_TableGolden(t *testing.T) {
	v, _ := Select(Options{From: t0.Add(-time.Minute), To: t0, By: "rule"})
	rows := []Row{
		{"group": json.RawMessage(`"AWSManagedRulesCommonRuleSet"`), "rule": json.RawMessage(`"SizeRestrictions_BODY"`), "matches": json.RawMessage(`50`),
			"terminating": json.RawMessage(`24`), "counted": json.RawMessage(`26`), "sites": json.RawMessage(`2`)},
		{"group": json.RawMessage(`"AWSManagedRulesKnownBadInputsRuleSet"`), "rule": json.RawMessage(`"Log4JRCE_HEADER"`), "matches": json.RawMessage(`3`),
			"terminating": json.RawMessage(`3`), "counted": json.RawMessage(`0`), "sites": json.RawMessage(`1`)},
	}
	var b bytes.Buffer
	if err := Write(&b, v, rows, "table"); err != nil {
		t.Fatal(err)
	}
	b.WriteString("--\n")
	if err := Write(&b, v, rows, "json"); err != nil {
		t.Fatal(err)
	}
	if *update {
		os.WriteFile("testdata/rule-table.golden", b.Bytes(), 0o644)
	}
	want, _ := os.ReadFile("testdata/rule-table.golden")
	if !bytes.Equal(b.Bytes(), want) {
		t.Errorf("golden mismatch:\n%s", b.String())
	}
	var js []map[string]any
	if err := json.Unmarshal(b.Bytes()[strings.Index(b.String(), "--\n")+3:], &js); err != nil || len(js) != 2 {
		t.Errorf("json output invalid: %v", err)
	}
}

func TestS3_CountedFilterInSQL(t *testing.T) {
	for _, w := range []time.Duration{time.Minute, 2 * time.Hour} {
		v, _ := Select(Options{From: t0.Add(-w), To: t0, By: "rule", Counted: true})
		if !strings.Contains(v.SQL, "({counted:UInt8} = 0 OR configured_action = 'COUNT')") {
			t.Errorf("%v: counted filter missing", w)
		}
	}
	if Params(Options{Counted: true})["counted"] != "1" || Params(Options{})["counted"] != "0" {
		t.Error("counted param")
	}
}
