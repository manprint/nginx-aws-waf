// Package stats implements `wafctl stats` (and the data of `wafctl report`).
package stats

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"nginxawswaf/wafctl/internal/ch"
	"nginxawswaf/wafctl/internal/logs"
)

// Views accepted by --by.
var Views = []string{"overview", "rule", "site", "path", "ip", "country", "user_class", "status"}

// Options select a stats view.
type Options struct {
	From, To   time.Time
	Sites      []string
	By         string
	Top        int
	Counted    bool
	SortBlocks bool
}

// AggThreshold: windows at least this long read the 1-minute aggregates.
const AggThreshold = time.Hour

// View is a resolved query: SQL, output columns and table headers.
type View struct {
	SQL     string
	Columns []string
	Headers []string
	Source  string // "events" | "agg"
}

var topKeys = map[string][2]string{
	"path":       {"path", "path"},
	"ip":         {"client_ip", "ip"},
	"country":    {"country", "country"},
	"user_class": {"user_class", "user_class"},
	"status":     {"status", "status"},
}

// Select picks SQL and columns for opts.
func Select(o Options) (View, error) {
	agg := o.To.Sub(o.From) >= AggThreshold
	src := map[bool]string{true: "agg", false: "events"}[agg]
	switch o.By {
	case "overview":
		cols := []string{"requests", "allow", "block", "fail", "shadow_block", "aws_default_block", "disagreements", "rps_avg"}
		return View{pick(agg, OverviewAgg, OverviewEvents), cols, upper(cols), src}, nil
	case "site":
		cols := []string{"site", "requests", "allow", "block", "fail", "aws_default_block", "disagreements"}
		return View{pick(agg, SiteAgg, SiteEvents), cols, upper(cols), src}, nil
	case "rule":
		cols := []string{"group", "rule", "matches", "terminating", "counted", "sites"}
		return View{pick(agg, RuleAgg, RuleEvents), cols, upper(cols), src}, nil
	}
	if k, ok := topKeys[o.By]; ok {
		cols := []string{k[1], "requests", "block", "fail", "disagreements"}
		return View{topSQL(k[0], k[1]), cols, upper(cols), "events"}, nil
	}
	return View{}, fmt.Errorf("--by %q not in %s", o.By, strings.Join(Views, "|"))
}

func pick(agg bool, a, e string) string {
	if agg {
		return a
	}
	return e
}

func upper(c []string) []string {
	o := make([]string, len(c))
	for i, s := range c {
		o[i] = strings.ToUpper(s)
	}
	return o
}

// Params returns the query parameters for opts.
func Params(o Options) map[string]string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	return map[string]string{
		"from_ms": strconv.FormatInt(o.From.UnixMilli(), 10), "to_ms": strconv.FormatInt(o.To.UnixMilli(), 10),
		"site": logs.ArrayParam(o.Sites), "top": strconv.Itoa(o.Top), "counted": b(o.Counted), "sort_blocks": b(o.SortBlocks),
	}
}

// Row is one result row (raw JSON values by column).
type Row map[string]json.RawMessage

// Run executes the view.
func Run(ctx context.Context, q ch.Querier, o Options) (View, []Row, error) {
	v, err := Select(o)
	if err != nil {
		return v, nil, err
	}
	rows, err := Query(ctx, q, v.SQL, o)
	return v, rows, err
}

// Query runs any stats SQL with the opts parameters.
func Query(ctx context.Context, q ch.Querier, sql string, o Options) ([]Row, error) {
	return ch.Collect[Row](ctx, q, sql, Params(o))
}

// Cell renders a JSON value as text (strings unquoted, empty as "-").
func Cell(v json.RawMessage) string {
	if len(v) > 0 && v[0] == '"' {
		var s string
		if json.Unmarshal(v, &s) == nil {
			if s == "" {
				return "-"
			}
			return s
		}
	}
	if len(v) == 0 {
		return "-"
	}
	return string(v)
}

// Write renders rows as an aligned table or a JSON array of objects with the view columns in order.
func Write(w io.Writer, v View, rows []Row, format string) error {
	if format == "json" {
		var b bytes.Buffer
		b.WriteString("[")
		for i, r := range rows {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString("\n  {")
			for j, c := range v.Columns {
				if j > 0 {
					b.WriteString(", ")
				}
				k, _ := json.Marshal(c)
				val := r[c]
				if len(val) == 0 {
					val = json.RawMessage("null")
				}
				fmt.Fprintf(&b, "%s: %s", k, val)
			}
			b.WriteString("}")
		}
		if len(rows) > 0 {
			b.WriteString("\n")
		}
		b.WriteString("]\n")
		_, err := w.Write(b.Bytes())
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(v.Headers, "\t"))
	for _, r := range rows {
		cells := make([]string, len(v.Columns))
		for i, c := range v.Columns {
			cells[i] = Cell(r[c])
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	return tw.Flush()
}
