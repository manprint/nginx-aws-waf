package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"nginxawswaf/wafctl/internal/logs"
	"nginxawswaf/wafctl/internal/stats"
)

// windowFlags registers --since/--from/--to/--site (shared by stats and report).
type windowFlags struct {
	since, from, to string
	sites           []string
}

func (w *windowFlags) add(fs *flag.FlagSet, defSince string) {
	fs.StringVar(&w.since, "since", defSince, "window ending now (e.g. 15m, 1h, 7d)")
	fs.StringVar(&w.from, "from", "", "window start, RFC3339 with zone")
	fs.StringVar(&w.to, "to", "", "window end, RFC3339 with zone (default now)")
	fs.Func("site", "site id (repeatable)", func(s string) error { w.sites = append(w.sites, s); return nil })
}

func (w *windowFlags) resolve(now time.Time) (time.Time, time.Time, error) {
	fs := flag.NewFlagSet("w", flag.ContinueOnError)
	ff := logs.AddFilterFlags(fs, w.since, 100)
	args := []string{"--since", w.since}
	if w.from != "" {
		args = append(args, "--from", w.from)
	}
	if w.to != "" {
		args = append(args, "--to", w.to)
	}
	if err := fs.Parse(args); err != nil {
		return time.Time{}, time.Time{}, err
	}
	f, err := ff.Finish(now)
	return f.From, f.To, err
}

func cmdStats(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	var w windowFlags
	w.add(fs, "1h")
	by := fs.String("by", "overview", "overview|rule|site|path|ip|country|user_class|status")
	top := fs.Int("top", 20, "rows for top-N views (1-10000)")
	counted := fs.Bool("counted", false, "--by rule: only rules configured as COUNT (would-block candidates)")
	sortBlocks := fs.Bool("sort-blocks", false, "top-N views: order by blocked requests")
	format := fs.String("format", "table", "table|json")
	raw := fs.String("raw", "", "query raw JSONL under DIR offline")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	from, to, err := w.resolve(time.Now())
	if err != nil {
		return fail("%v", err)
	}
	if *top < 1 || *top > 10000 {
		return fail("--top %d not in 1-10000", *top)
	}
	if *counted && *by != "rule" {
		return fail("--counted needs --by rule")
	}
	if *format != "table" && *format != "json" {
		return fail("--format %q not in table|json", *format)
	}
	o := stats.Options{From: from, To: to, Sites: w.sites, By: *by, Top: *top, Counted: *counted, SortBlocks: *sortBlocks}
	v, rows, err := stats.Run(context.Background(), querier(*raw), o)
	if err != nil {
		return fail("%v", err)
	}
	if *format == "table" {
		fmt.Printf("# %s .. %s UTC · source %s\n", from.Format("2006-01-02 15:04:05"), to.Format("2006-01-02 15:04:05"), v.Source)
	}
	if err := stats.Write(os.Stdout, v, rows, *format); err != nil {
		return fail("%v", err)
	}
	return 0
}
