// Package report renders the self-contained HTML report (`wafctl report --html`).
package report

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"nginxawswaf/wafctl/internal/ch"
	"nginxawswaf/wafctl/internal/stats"
)

//go:embed template.html
var tmplFS embed.FS

var tmpl = template.Must(template.ParseFS(tmplFS, "template.html"))

// SectionIDs are the report sections, in order.
var SectionIDs = []string{"summary", "timeline", "terminating", "counted", "disagreements", "paths", "clients", "fails", "config"}

// Cell is one table cell.
type Cell struct {
	Text string
	Num  bool
}

// Table is a table section.
type Table struct {
	ID, Title, Note string
	Headers         []string
	Rows            [][]Cell
	Chart           template.HTML
}

// KV is one summary figure.
type KV struct{ Label, Value string }

// Data is everything the template needs.
type Data struct {
	From, To, Generated, Sites, Source string
	Summary                            []KV
	TimelineChart                      template.HTML
	Tables                             []Table
	Config                             string
}

// Render writes the HTML.
func Render(w io.Writer, d Data) error { return tmpl.Execute(w, d) }

// Options for Build.
type Options struct {
	From, To time.Time
	Sites    []string
	Top      int
	Config   string // config snapshot text (meta.json + compat lines), "" if not on a node
	Now      time.Time
}

// Build queries ClickHouse (reusing the stats SQL) and assembles the report data.
func Build(ctx context.Context, q ch.Querier, o Options) (Data, error) {
	so := stats.Options{From: o.From, To: o.To, Sites: o.Sites, Top: o.Top}
	sites := "tutti"
	if len(o.Sites) > 0 {
		sites = strings.Join(o.Sites, ", ")
	}
	d := Data{From: fmtT(o.From), To: fmtT(o.To), Generated: fmtT(o.Now), Sites: sites, Config: o.Config}
	run := func(by string, f func(*stats.Options)) (stats.View, []stats.Row, error) {
		x := so
		x.By = by
		if f != nil {
			f(&x)
		}
		return stats.Run(ctx, q, x)
	}
	// 1 summary
	v, rows, err := run("overview", nil)
	if err != nil {
		return d, err
	}
	d.Source = v.Source
	labels := map[string]string{"requests": "Richieste", "allow": "ALLOW", "block": "BLOCK", "fail": "FAIL", "shadow_block": "Shadow BLOCK",
		"aws_default_block": "BLOCK (AWS default)", "disagreements": "Disaccordi vs AWS default", "rps_avg": "RPS medio"}
	for _, c := range v.Columns {
		val := "0"
		if len(rows) > 0 {
			val = stats.Cell(rows[0][c])
		}
		d.Summary = append(d.Summary, KV{labels[c], val})
	}
	// 2 timeline
	tl, err := stats.Query(ctx, q, stats.Timeline, so)
	if err != nil {
		return d, err
	}
	var st []Stack
	for _, r := range tl {
		st = append(st, Stack{stats.Cell(r["hour"]), f64(r["allow"]), f64(r["block"]), f64(r["fail"])})
	}
	if len(st) > 0 {
		d.TimelineChart = Columns(st)
	}
	// 3 terminating rules, 4 counted rules
	v, rows, err = run("rule", nil)
	if err != nil {
		return d, err
	}
	var term []stats.Row
	for _, r := range rows {
		if f64(r["terminating"]) > 0 {
			term = append(term, r)
		}
	}
	sort.SliceStable(term, func(i, j int) bool { return f64(term[i]["terminating"]) > f64(term[j]["terminating"]) })
	d.Tables = append(d.Tables, table("terminating", "3. Regole terminanti (top)", "Match prima del punto terminante con azione ≠ COUNT.", v, term, "rule", "terminating", "#c0392b"))
	v, rows, err = run("rule", func(x *stats.Options) { x.Counted = true })
	if err != nil {
		return d, err
	}
	d.Tables = append(d.Tables, table("counted", "4. Regole in COUNT (candidati would-block)", "Regole configurate COUNT che hanno matchato: bloccherebbero se riportate a BLOCK.", v, rows, "rule", "matches", "#e67e22"))
	// 5 disagreements
	dr, err := stats.Query(ctx, q, stats.Disagreements, so)
	if err != nil {
		return d, err
	}
	dv := stats.View{Columns: []string{"action", "aws_default_action", "aws_default_rule", "terminating_rule", "path", "requests"},
		Headers: []string{"ACTION", "AWS DEFAULT", "AWS DEFAULT RULE", "TERMINATING", "PATH", "REQUESTS"}}
	d.Tables = append(d.Tables, table("disagreements", "5. Disaccordi con l'ACL AWS di default", "Richieste in cui l'azione del simulatore differisce dall'ACL one-click AWS non tarata.", dv, dr, "", "", ""))
	// 6 blocked paths
	v, rows, err = run("path", func(x *stats.Options) { x.SortBlocks = true })
	if err != nil {
		return d, err
	}
	d.Tables = append(d.Tables, table("paths", "6. Path più bloccati", "", v, rows, "path", "block", "#c0392b"))
	// 7 clients: IPs + countries in one section
	v, rows, err = run("ip", func(x *stats.Options) { x.SortBlocks = true })
	if err != nil {
		return d, err
	}
	t := table("clients", "7. Client IP e paesi", "IP ordinati per richieste bloccate; i paesi richiedono il DB GeoIP.", v, rows, "ip", "block", "#c0392b")
	cv, crows, err := run("country", nil)
	if err != nil {
		return d, err
	}
	var bars []Bar
	for _, r := range crows {
		bars = append(bars, Bar{stats.Cell(r["country"]), f64(r["requests"])})
	}
	t.Chart += HBars(bars, "#2c7fb8")
	ct := table("", "", "", cv, crows, "", "", "")
	t.Rows = append(t.Rows, []Cell{{Text: "— paesi —"}})
	t.Rows = append(t.Rows, ct.Rows...)
	d.Tables = append(d.Tables, t)
	// 8 fails
	fr, err := stats.Query(ctx, q, stats.Fails, so)
	if err != nil {
		return d, err
	}
	fv := stats.View{Columns: []string{"ts", "site", "fail_reason", "method", "path", "status", "request_id"},
		Headers: []string{"TS", "SITE", "REASON", "METHOD", "PATH", "STATUS", "RID"}}
	d.Tables = append(d.Tables, table("fails", "8. Eventi FAIL (errori interni del WAF)", "", fv, fr, "", "", ""))
	return d, nil
}

// table converts stats rows; when barLabel != "" it adds a bar chart of barValue.
func table(id, title, note string, v stats.View, rows []stats.Row, barLabel, barValue, color string) Table {
	t := Table{ID: id, Title: title, Note: note, Headers: v.Headers}
	var bars []Bar
	for _, r := range rows {
		cells := make([]Cell, len(v.Columns))
		for i, c := range v.Columns {
			raw := r[c]
			cells[i] = Cell{Text: trunc(stats.Cell(raw), 160), Num: len(raw) > 0 && raw[0] != '"'}
		}
		t.Rows = append(t.Rows, cells)
		if barLabel != "" {
			bars = append(bars, Bar{stats.Cell(r[barLabel]), f64(r[barValue])})
		}
	}
	if len(bars) > 0 {
		t.Chart = HBars(bars, color)
	}
	return t
}

func f64(v json.RawMessage) float64 {
	s := strings.Trim(string(v), `"`)
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func fmtT(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }
