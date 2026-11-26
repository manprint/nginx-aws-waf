package testrun

import (
	"strings"
	"testing"
)

func TestT4_RetargetAndException(t *testing.T) {
	cases := []Case{
		{ID: "a", Site: "demo", Expect: Expect{Status: 403, TerminatingRule: "X"}},
		{ID: "b", Site: "demo", Expect: Expect{Status: 403, TerminatingRule: "Y"}},
		{ID: "c", Site: "tuned", Expect: Expect{Status: 200, TerminatingRule: "Default_Action"}},
	}
	m, err := ParseRetarget("demo=shop12,tuned=shop12")
	if err != nil {
		t.Fatal(err)
	}
	ex := []Exception{{Case: "b", Sites: []string{"shop12"}, Expect: Expect{Status: 200, TerminatingRule: "Default_Action"}, Reason: "r"},
		{Case: "a", Sites: []string{"shop14"}, Expect: Expect{Status: 1, TerminatingRule: "Z"}, Reason: "r"}}
	out := Retarget(cases, m, ex)
	if out[0].Site != "shop12" || out[0].Expect.TerminatingRule != "X" {
		t.Errorf("a: %+v (exception for another site must not apply)", out[0])
	}
	if out[1].Site != "shop12" || out[1].Expect.Status != 200 || out[1].Expect.TerminatingRule != "Default_Action" {
		t.Errorf("b: %+v", out[1])
	}
	if out[2].Site != "tuned" {
		t.Errorf("special site retargeted: %+v", out[2])
	}
	if f := FilterSite(cases, "demo"); len(f) != 2 {
		t.Errorf("filter-site: %d", len(f))
	}
	if _, err := ParseRetarget("demo"); err == nil {
		t.Error("bad retarget accepted")
	}
}

func TestT5_ExceptionNeedsReason(t *testing.T) {
	bad := "version: 1\nexceptions:\n  - case: a\n    sites: [shop12]\n    expect: {status: 200, terminating_rule: Default_Action}\n"
	if _, err := ParseExceptions([]byte(bad)); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("missing reason accepted: %v", err)
	}
	if ex, err := ParseExceptions([]byte(bad + "    reason: ok\n")); err != nil || len(ex) != 1 {
		t.Fatalf("valid file rejected: %v", err)
	}
	if ex, err := ParseExceptions([]byte("version: 1\nexceptions: []\n")); err != nil || len(ex) != 0 {
		t.Fatalf("empty list: %v", err)
	}
}
