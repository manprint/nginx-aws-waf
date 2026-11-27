package logs

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"nginxawswaf/wafctl/internal/ch"
)

// matchTuple is the named tuple type of the per-request matches array.
const matchTuple = "Tuple(rule_id UInt32, rule_name String, rule_group String, configured_action String, in_scope UInt8, post_terminating UInt8, variable String, value String)"

// ExportSQL returns the streaming export query. withMatches adds a "matches" array column
// (LEFT JOIN on request_id within the same window, sorted by rule id = evaluation order).
func ExportSQL(where string, cols []string, withMatches bool) string {
	sel := "*"
	if cols != nil {
		sel = strings.Join(cols, ", ")
	}
	if !withMatches {
		return "SELECT " + sel + " FROM waf.events WHERE " + where + " ORDER BY ts, request_id"
	}
	mwhere := "ts >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC') AND ts < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')"
	return "SELECT e.*, m.matches FROM (SELECT " + sel + " FROM waf.events WHERE " + where + ") AS e" +
		" LEFT JOIN (SELECT request_id, CAST(arraySort(x -> x.1, groupArray(tuple(rule_id, rule_name, rule_group, configured_action, in_scope, post_terminating, variable, value))), 'Array(" + matchTuple + ")') AS matches" +
		" FROM waf.matches WHERE " + mwhere + " GROUP BY request_id) AS m ON e.request_id = m.request_id ORDER BY e.ts, e.request_id"
}

// CSVColumns are the events columns exported as CSV: all except headers and body.
func CSVColumns() ([]string, error) {
	cols, err := ch.Columns(ch.SchemaSQL(), "events")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range cols {
		n := strings.Fields(c)[0]
		if n == "request_headers" || n == "response_headers" || n == "request_body" {
			continue
		}
		out = append(out, n)
	}
	return out, nil
}

// Export streams the events of f to w as jsonl, csv or aws; it returns the number of rows.
func Export(ctx context.Context, q ch.Querier, f Filter, format string, withMatches, gz bool, w io.Writer) (int, error) {
	if gz {
		zw := gzip.NewWriter(w)
		defer zw.Close()
		w = zw
	}
	bw := bufio.NewWriterSize(w, 256<<10)
	defer bw.Flush()
	where, p := f.Where()
	n := 0
	switch format {
	case "jsonl":
		err := q.Query(ctx, ExportSQL(where, nil, withMatches), p, func(m json.RawMessage) error {
			n++
			_, err := fmt.Fprintf(bw, "%s\n", m)
			return err
		})
		return n, err
	case "csv":
		cols, err := CSVColumns()
		if err != nil {
			return 0, err
		}
		cw := csv.NewWriter(bw)
		if err := cw.Write(cols); err != nil {
			return 0, err
		}
		rec := make([]string, len(cols))
		err = q.Query(ctx, ExportSQL(where, cols, false), p, func(m json.RawMessage) error {
			var row map[string]json.RawMessage
			if err := json.Unmarshal(m, &row); err != nil {
				return err
			}
			for i, c := range cols {
				rec[i] = csvValue(row[c])
			}
			n++
			return cw.Write(rec)
		})
		cw.Flush()
		if err == nil {
			err = cw.Error()
		}
		return n, err
	case "aws":
		err := q.Query(ctx, ExportSQL(where, nil, true), p, func(m json.RawMessage) error {
			var ev Event
			if err := json.Unmarshal(m, &ev); err != nil {
				return err
			}
			b, err := MarshalAWS(ToAWS(ev, ev.Matches))
			if err != nil {
				return err
			}
			n++
			_, err = bw.Write(b)
			return err
		})
		return n, err
	}
	return 0, fmt.Errorf("--format %q not in jsonl|csv|aws", format)
}

// csvValue renders a JSON value as a CSV cell: strings unquoted, everything else as JSON text.
func csvValue(v json.RawMessage) string {
	if len(v) > 0 && v[0] == '"' {
		var s string
		if json.Unmarshal(v, &s) == nil {
			return s
		}
	}
	return string(v)
}
