package report

import (
	"bytes"
	"html/template"
	"regexp"
	"strings"
	"testing"
)

func fixture() Data {
	return Data{From: "2026-11-27 09:00:00", To: "2026-11-27 10:00:00", Generated: "2026-11-27 10:00:01", Sites: "tutti", Source: "agg",
		Summary:       []KV{{"Richieste", "10"}, {"BLOCK", "3"}},
		TimelineChart: Columns([]Stack{{"2026-11-27 09:00:00", 7, 3, 0}}),
		Tables: []Table{
			{ID: "terminating", Title: "3", Headers: []string{"RULE", "N"}, Rows: [][]Cell{{{Text: "NoUserAgent_HEADER"}, {Text: "3", Num: true}}},
				Chart: HBars([]Bar{{"NoUserAgent_HEADER", 3}}, "#c00")},
			{ID: "counted", Title: "4"}, {ID: "disagreements", Title: "5"},
			{ID: "paths", Title: "6", Headers: []string{"PATH"}, Rows: [][]Cell{{{Text: `<script>alert("x")</script> http://evil.example/`}}}},
			{ID: "clients", Title: "7"}, {ID: "fails", Title: "8"},
		},
		Config: `{"node_id":"n1"}`,
	}
}

func TestH1_SelfContainedWithSections(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, fixture()); err != nil {
		t.Fatal(err)
	}
	h := b.String()
	if m := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?(https?:)?//`).FindString(h); m != "" {
		t.Errorf("external reference: %s", m)
	}
	if strings.Contains(h, "<script") || strings.Contains(h, "<link") {
		t.Error("script/link element present (user data must be escaped)")
	}
	last := -1
	for _, id := range SectionIDs {
		i := strings.Index(h, `<section id="`+id+`"`)
		if i < 0 {
			t.Errorf("section %s missing", id)
		} else if i < last {
			t.Errorf("section %s out of order", id)
		}
		last = i
	}
	if !strings.Contains(h, "<svg") || !strings.Contains(h, "NoUserAgent_HEADER") {
		t.Error("charts or data missing")
	}
}

func TestH2_ZeroValuesNoDivByZero(t *testing.T) {
	for _, s := range []template.HTML{
		HBars([]Bar{{"a", 0}, {"b", 0}}, "#000"),
		HBars(nil, "#000"),
		Columns([]Stack{{"2026-11-27 09:00:00", 0, 0, 0}, {"2026-11-27 10:00:00", 0, 0, 0}}),
		Columns(nil),
	} {
		str := string(s)
		if strings.Contains(str, "NaN") || strings.Contains(str, "Inf") || !strings.HasPrefix(str, "<svg") {
			t.Errorf("bad svg: %.200s", str)
		}
	}
}
