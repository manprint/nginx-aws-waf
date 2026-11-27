package logs

import (
	"flag"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

func parse(t *testing.T, args ...string) (Filter, error) {
	t.Helper()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	ff := AddFilterFlags(fs, "1h", 100)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return ff.Finish(now)
}

func TestQ1_FiltersArePlaceholders(t *testing.T) {
	evil := "x' OR 1=1 --"
	f, err := parse(t, "--site", "demo", "--site", evil, "--action", "BLOCK", "--shadow", "BLOCK", "--rule", "Evil'Rule",
		"--ip", "2001:db8::1", "--country", "G'B", "--path-prefix", "/a'b", "--user-class", "web'site", "--status", "403", "--rid", "r'id", "--limit", "7")
	if err != nil {
		t.Fatal(err)
	}
	where, p := f.Where()
	sql := SearchSQL(where)
	for _, v := range []string{evil, "Evil'Rule", "2001:db8::1", "G'B", "/a'b", "web'site", "r'id", "demo", "403"} {
		if strings.Contains(sql, v) {
			t.Errorf("value %q appears in SQL: %s", v, sql)
		}
	}
	for _, ph := range []string{"{site:Array(String)}", "{action:String}", "{shadow:String}", "{rule:String}", "{ip:String}", "{country:String}",
		"{path_prefix:String}", "{user_class:String}", "{status:UInt16}", "{rid:String}", "{from_ms:Int64}", "{to_ms:Int64}", "{limit:UInt32}"} {
		if !strings.Contains(sql, ph) {
			t.Errorf("placeholder %s missing", ph)
		}
	}
	if p["site"] != `['demo','x\' OR 1=1 --']` || p["rule"] != "Evil'Rule" || p["status"] != "403" {
		t.Errorf("params %v", p)
	}
	if p["from_ms"] != "1795770000000" || p["to_ms"] != "1795773600000" {
		t.Errorf("window %s..%s", p["from_ms"], p["to_ms"])
	}
	f2, _ := parse(t, "--rule", "NoUserAgent_HEADER", "--matched")
	w2, _ := f2.Where()
	if !strings.Contains(w2, "FROM waf.matches WHERE rule_name = {rule:String}") {
		t.Errorf("matched rule: %s", w2)
	}
	if _, err := parse(t, "--action", "DROP"); err == nil {
		t.Error("bad action accepted")
	}
	if _, err := parse(t, "--limit", "100001"); err == nil {
		t.Error("limit > 100000 accepted")
	}
	if _, err := parse(t, "--ip", "1.2.3"); err == nil {
		t.Error("bad ip accepted")
	}
}

func TestQ2_FromNeedsZone(t *testing.T) {
	if _, err := parse(t, "--from", "2026-11-27T08:00:00"); err == nil {
		t.Error("--from without zone accepted")
	}
	f, err := parse(t, "--from", "2026-11-27T09:00:00+01:00", "--to", "2026-11-27T09:30:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if f.From != time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC) || f.To != time.Date(2026, 11, 27, 9, 30, 0, 0, time.UTC) {
		t.Errorf("window %v %v", f.From, f.To)
	}
	if _, err := parse(t, "--to", "2026-11-27T09:30:00Z"); err == nil {
		t.Error("--to without --from accepted")
	}
	if d, err := ParseDuration("7d"); err != nil || d != 168*time.Hour {
		t.Errorf("7d: %v %v", d, err)
	}
}
