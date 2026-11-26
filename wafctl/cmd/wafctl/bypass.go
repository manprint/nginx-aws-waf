package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"nginxawswaf/wafctl/internal/bypass"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
)

var nowFn = time.Now

func whoami() string {
	for _, k := range []string{"SUDO_USER", "USER", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "unknown"
}

func cmdBypass(args []string) int {
	dir := env.ConfigDir()
	path := bypass.Path(dir)
	st, err := bypass.Load(path)
	if err != nil {
		return fail("%v", err)
	}
	if len(args) == 0 {
		return fail("usage: wafctl bypass <site> --ttl <dur> --reason <text> | list | clear <site> | expire")
	}
	switch args[0] {
	case "list":
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SITE\tUNTIL\tACTIVE\tBY\tREASON")
		ids := make([]string, 0, len(st.Sites))
		for id := range st.Sites {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			e := st.Sites[id]
			fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\n", id, e.Until.UTC().Format(time.RFC3339), e.Until.After(nowFn()), e.By, e.Reason)
		}
		tw.Flush()
		return 0
	case "clear":
		if len(args) != 2 {
			return fail("usage: wafctl bypass clear <site>")
		}
		if _, ok := st.Sites[args[1]]; !ok {
			return fail("no bypass for site %s", args[1])
		}
		delete(st.Sites, args[1])
		if err := st.Save(path); err != nil {
			return fail("%v", err)
		}
		return doApply(dir, false)
	case "expire":
		gone := st.Expire(nowFn())
		if len(gone) == 0 {
			return 0
		}
		if err := st.Save(path); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("expired: %v\n", gone)
		return doApply(dir, false)
	}
	site := args[0]
	fs := flag.NewFlagSet("bypass", flag.ContinueOnError)
	ttl := fs.Duration("ttl", 0, "duration 1m-72h")
	reason := fs.String("reason", "", "reason (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *ttl < time.Minute || *ttl > 72*time.Hour {
		fmt.Fprintln(os.Stderr, "wafctl: --ttl must be between 1m and 72h")
		return 2
	}
	if *reason == "" {
		fmt.Fprintln(os.Stderr, "wafctl: --reason is required")
		return 2
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return fail("%v", err)
	}
	if cfg.Site(site) == nil {
		fmt.Fprintf(os.Stderr, "wafctl: unknown site %q\n", site)
		return 2
	}
	now := nowFn().UTC()
	st.Sites[site] = bypass.Entry{Until: now.Add(*ttl), Reason: *reason, By: whoami(), Created: now}
	if err := st.Save(path); err != nil {
		return fail("%v", err)
	}
	return doApply(dir, false)
}
