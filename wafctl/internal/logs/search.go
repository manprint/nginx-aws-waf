package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"nginxawswaf/wafctl/internal/ch"
)

// Row is one search/tail result row.
type Row struct {
	TS              string `json:"ts"`
	SiteID          string `json:"site_id"`
	ClientIP        string `json:"client_ip"`
	Country         string `json:"country"`
	Method          string `json:"method"`
	Path            string `json:"path"`
	Status          int    `json:"status"`
	Action          string `json:"action"`
	ShadowAction    string `json:"shadow_action"`
	TerminatingRule string `json:"terminating_rule"`
	RequestID       string `json:"request_id"`
}

const rowCols = "ts, site_id, client_ip, country, method, path, status, action, shadow_action, terminating_rule, request_id"

// SearchSQL returns the search query for a WHERE clause built by Filter.Where.
func SearchSQL(where string) string {
	return "SELECT " + rowCols + " FROM waf.events WHERE " + where + " ORDER BY ts DESC, request_id LIMIT {limit:UInt32}"
}

// Search runs the search query (newest first).
func Search(ctx context.Context, q ch.Querier, f Filter) ([]Row, error) {
	where, p := f.Where()
	p["limit"] = fmt.Sprint(f.Limit)
	rows, err := ch.Collect[Row](ctx, q, SearchSQL(where), p)
	for i := range rows {
		rows[i].TS = TS(rows[i].TS)
	}
	return rows, err
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// WriteRows prints rows as a table (header optional) or as a JSON array.
func WriteRows(w io.Writer, rows []Row, format string, header bool) error {
	if format == "json" {
		if rows == nil {
			rows = []Row{}
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(rows)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if header {
		fmt.Fprintln(tw, "TS\tSITE\tIP\tCC\tMETHOD\tPATH\tSTATUS\tACTION\tSHADOW\tTERMINATING\tRID")
	}
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", r.TS, dash(r.SiteID), r.ClientIP, dash(r.Country),
			r.Method, trunc(r.Path, 60), r.Status, r.Action, dash(r.ShadowAction), r.TerminatingRule, r.RequestID)
	}
	return tw.Flush()
}
