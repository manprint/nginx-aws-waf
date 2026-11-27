package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"nginxawswaf/wafctl/internal/ch"
)

// Match is one waf.matches row.
type Match struct {
	RuleName         string `json:"rule_name"`
	RuleGroup        string `json:"rule_group"`
	ConfiguredAction string `json:"configured_action"`
	InScope          int    `json:"in_scope"`
	PostTerminating  int    `json:"post_terminating"`
	Variable         string `json:"variable"`
	Value            string `json:"value"`
}

const (
	showEventSQL   = "SELECT * FROM waf.events WHERE request_id = {rid:String} ORDER BY ts DESC LIMIT 1"
	showMatchesSQL = "SELECT rule_name, rule_group, configured_action, in_scope, post_terminating, variable, value FROM waf.matches WHERE request_id = {rid:String} ORDER BY post_terminating, rule_group, rule_name"
)

// Show prints one event (pretty JSON) and its matches.
func Show(ctx context.Context, q ch.Querier, rid, format string, w io.Writer) error {
	p := map[string]string{"rid": rid}
	evs, err := ch.Collect[map[string]any](ctx, q, showEventSQL, p)
	if err != nil {
		return err
	}
	if len(evs) == 0 {
		return fmt.Errorf("request %s not found", rid)
	}
	ev := evs[0]
	if s, ok := ev["ts"].(string); ok {
		ev["ts"] = TS(s)
	}
	ms, err := ch.Collect[Match](ctx, q, showMatchesSQL, p)
	if err != nil {
		return err
	}
	if format == "json" {
		if ms == nil {
			ms = []Match{}
		}
		ev["matches"] = ms
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(ev)
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.SetEscapeHTML(false)
	if err := e.Encode(ev); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nmatches (%d):\n", len(ms))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tGROUP\tACTION\tINSCOPE\tPOST\tVAR\tVALUE")
	for _, m := range ms {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", m.RuleName, m.RuleGroup, m.ConfiguredAction, m.InScope, m.PostTerminating, m.Variable, trunc(m.Value, 80))
	}
	return tw.Flush()
}
