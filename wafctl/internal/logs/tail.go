package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"nginxawswaf/wafctl/internal/ch"
)

// TailSQL selects rows at or after {after_ms}, oldest first.
func TailSQL(where string) string {
	return "SELECT " + rowCols + " FROM waf.events WHERE " + where +
		" AND ts >= fromUnixTimestamp64Milli({after_ms:Int64}, 'UTC') ORDER BY ts, request_id LIMIT {limit:UInt32}"
}

// Tail polls every interval for rows newer than the last seen one and prints them until ctx ends.
// Rows with the same ts as the last one are de-duplicated by request_id.
func Tail(ctx context.Context, q ch.Querier, f Filter, format string, interval time.Duration, w io.Writer) error {
	after := f.From
	seen := map[string]bool{}
	header := true
	for {
		f.To = time.Now().UTC().Add(time.Hour) // open-ended
		where, p := f.Where()
		p["after_ms"] = fmt.Sprint(after.UnixMilli())
		p["limit"] = fmt.Sprint(f.Limit)
		rows, err := ch.Collect[Row](ctx, q, TailSQL(where), p)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		var out []Row
		for _, r := range rows {
			if seen[r.RequestID] {
				continue
			}
			t, err := time.Parse("2006-01-02 15:04:05.000", r.TS)
			if err == nil && t.After(after) {
				after, seen = t, map[string]bool{}
			}
			seen[r.RequestID] = true
			r.TS = TS(r.TS)
			out = append(out, r)
		}
		if len(out) > 0 {
			if format == "json" {
				for _, r := range out { // JSON lines
					b, _ := json.Marshal(r)
					fmt.Fprintf(w, "%s\n", b)
				}
			} else if err := WriteRows(w, out, "table", header); err != nil {
				return err
			}
			header = false
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}
