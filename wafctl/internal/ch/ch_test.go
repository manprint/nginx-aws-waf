package ch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestQ3_ClientDecodesAndSurfacesErrors(t *testing.T) {
	var gotQuery, gotParam, gotUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1024)
		n, _ := r.Body.Read(b)
		gotQuery = string(b[:n])
		gotParam = r.URL.Query().Get("param_site")
		gotUser, _, _ = r.BasicAuth()
		if strings.Contains(gotQuery, "boom") {
			http.Error(w, "Code: 62. DB::Exception: Syntax error", 500)
			return
		}
		w.Write([]byte("{\"a\":1}\n{\"a\":2}\n"))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, User: "waf_ro", Password: "x"}
	type row struct{ A int }
	rows, err := Collect[row](context.Background(), c, "SELECT {site:String}", map[string]string{"site": "demo"})
	if err != nil || len(rows) != 2 || rows[1].A != 2 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	if gotParam != "demo" || gotUser != "waf_ro" || gotQuery != "SELECT {site:String}" {
		t.Errorf("request: q=%q param=%q user=%q", gotQuery, gotParam, gotUser)
	}
	err = c.Query(context.Background(), "boom", nil, func(json.RawMessage) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), "Syntax error") {
		t.Errorf("error not surfaced: %v", err)
	}
}

func TestQ4_SchemaColumns(t *testing.T) {
	deploy, err := os.ReadFile("../../../deploy/clickhouse/initdb/001-schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if string(deploy) != SchemaSQL() {
		t.Fatal("migrations/001-schema.sql differs from deploy/clickhouse/initdb/001-schema.sql")
	}
	// expected count straight from the DDL text: lines inside the events column list
	s := string(deploy)
	body := s[strings.Index(s, "CREATE TABLE IF NOT EXISTS waf.events"):]
	body = body[strings.Index(body, "(")+1 : strings.Index(body, "\n)")]
	want := 0
	for _, l := range strings.Split(body, "\n") {
		if strings.TrimSpace(l) != "" {
			want++
		}
	}
	cols, err := Columns(SchemaSQL(), "events")
	if err != nil || len(cols) != want {
		t.Fatalf("events columns %d, want %d (%v)", len(cols), want, err)
	}
	t.Logf("events columns: %d", len(cols))
	for _, c := range cols {
		if strings.Contains(c, "CODEC") || strings.HasSuffix(c, ",") {
			t.Errorf("column not cleaned: %q", c)
		}
	}
	pre, err := Prelude()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"CREATE VIEW waf.events", "CREATE VIEW waf.matches", "CREATE VIEW waf.agg_requests_1m", "CREATE VIEW waf.agg_matches_1m", `DateTime64(3, \'UTC\')`} {
		if !strings.Contains(pre, w) {
			t.Errorf("prelude lacks %q", w)
		}
	}
}

func TestQR1_RawPassesParams(t *testing.T) {
	var args []string
	var stdin string
	r := &Raw{Dir: "/tmp", Run: func(_ context.Context, a []string, in []byte) ([]byte, error) {
		args, stdin = a, string(in)
		return []byte("{\"n\":5}\n"), nil
	}}
	type row struct{ N int }
	rows, err := Collect[row](context.Background(), r, "SELECT count() AS n FROM waf.events WHERE site_id = {s:String}", map[string]string{"s": "demo"})
	if err != nil || len(rows) != 1 || rows[0].N != 5 {
		t.Fatalf("%v %v", rows, err)
	}
	if !strings.Contains(strings.Join(args, " "), "--param_s=demo") || !strings.HasSuffix(stdin, "{s:String};\n") {
		t.Errorf("args %v stdin tail %q", args, stdin[len(stdin)-40:])
	}
}
