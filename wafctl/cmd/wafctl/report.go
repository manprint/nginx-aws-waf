package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxawswaf/wafctl/internal/ch"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/report"
)

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	var w windowFlags
	w.add(fs, "24h")
	htmlOut := fs.Bool("html", false, "write a self-contained HTML report (required)")
	out := fs.String("o", "", "output file")
	top := fs.Int("top", 20, "rows per table")
	raw := fs.String("raw", "", "query raw JSONL under DIR offline")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*htmlOut || *out == "" {
		return fail("usage: wafctl report --html [--since 24h | --from T [--to T]] [--site S] [--top 20] -o FILE")
	}
	from, to, err := w.resolve(time.Now())
	if err != nil {
		return fail("%v", err)
	}
	now := time.Now().UTC()
	d, err := report.Build(context.Background(), querier(*raw), report.Options{From: from, To: to, Sites: w.sites, Top: *top, Config: configSnapshot(), Now: now})
	if err != nil {
		return fail("%v", err)
	}
	var b bytes.Buffer
	if err := report.Render(&b, d); err != nil {
		return fail("%v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return fail("%v", err)
	}
	if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "report written: %s (%d bytes)\n", *out, b.Len())
	return 0
}

// configSnapshot returns meta.json of the current rev plus one compat line per site, or "" off-node.
func configSnapshot() string {
	dir := env.ConfigDir()
	if _, err := os.Stat(filepath.Join(dir, "node.yaml")); err != nil {
		return ""
	}
	var b strings.Builder
	if m, err := os.ReadFile(filepath.Join(env.DataDir(), "runtime", "current", "meta.json")); err == nil {
		var pretty bytes.Buffer
		if json.Indent(&pretty, bytes.TrimSpace(m), "", "  ") == nil {
			b.WriteString("meta.json:\n" + pretty.String() + "\n\n")
		}
	}
	cat, err := loadCatalog()
	if err != nil {
		return b.String()
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return b.String()
	}
	for _, s := range cfg.Sites {
		e, err := config.Effective(cfg, s.SiteID, cat, false)
		if err != nil {
			continue
		}
		if r := config.Compat(e, cat); len(r) > 0 {
			fmt.Fprintf(&b, "site %s: nginx-only (%s)\n", s.SiteID, strings.Join(r, "; "))
		} else {
			fmt.Fprintf(&b, "site %s: aws-compatible\n", s.SiteID)
		}
	}
	return b.String()
}

func cmdCH(args []string) int {
	usage := "usage: wafctl ch migrate | wafctl ch retention [--raw-days N] [--agg-days M]"
	if len(args) == 0 {
		return fail("%s", usage)
	}
	ctx := context.Background()
	q := ch.AdminFromEnv(env.ConfigDir())
	switch args[0] {
	case "migrate":
		log, err := ch.Migrate(ctx, q)
		for _, l := range log {
			fmt.Println(l)
		}
		if err != nil {
			return fail("%v", err)
		}
		return 0
	case "retention":
		fs := flag.NewFlagSet("ch retention", flag.ContinueOnError)
		rawDays := fs.Int("raw-days", 0, "TTL in days of waf.events and waf.matches (1-3650)")
		aggDays := fs.Int("agg-days", 0, "TTL in days of waf.agg_* (>= raw days)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		cur, err := ch.Retention(ctx, q)
		if err != nil {
			return fail("%v", err)
		}
		if *rawDays != 0 || *aggDays != 0 {
			days := map[string]int{}
			for _, t := range cur {
				days[t.Table] = t.Days
			}
			if err := ch.ValidateRetention(*rawDays, *aggDays, days["events"], days["agg_requests_1m"]); err != nil {
				return fail("%v", err)
			}
			if err := ch.SetRetention(ctx, q, *rawDays, *aggDays); err != nil {
				return fail("%v", err)
			}
			if cur, err = ch.Retention(ctx, q); err != nil {
				return fail("%v", err)
			}
		}
		for _, t := range cur {
			fmt.Printf("%-16s %4d DAY  (%s)\n", t.Table, t.Days, t.TTL)
		}
		return 0
	}
	return fail("%s", usage)
}
