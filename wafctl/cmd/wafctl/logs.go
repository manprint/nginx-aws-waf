package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nginxawswaf/wafctl/internal/apply"
	"nginxawswaf/wafctl/internal/ch"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/logs"
)

const logsUsage = `usage: wafctl logs <command>
  search [filters] [--format table|json] [--raw DIR]
  show <request_id> [--format table|json] [--raw DIR]
  tail [filters] [--format table|json] [--interval 2s]
  rotate [--max-size 512MiB] [--keep-hours 24] [--raw-days 7]
filters: --site S (repeatable) --since 1h | --from RFC3339 [--to RFC3339] --action ALLOW|BLOCK|FAIL
         --shadow BLOCK --rule NAME [--matched] --ip IP --country CC --path-prefix P --user-class C
         --status N --rid ID --limit N`

func cmdLogs(args []string) int {
	if len(args) == 0 {
		return fail("%s", logsUsage)
	}
	switch args[0] {
	case "search", "tail":
		return cmdLogsQuery(args[0], args[1:])
	case "show":
		return cmdLogsShow(args[1:])
	case "rotate":
	default:
		return fail("%s", logsUsage)
	}
	fs := flag.NewFlagSet("logs rotate", flag.ContinueOnError)
	maxSize := fs.String("max-size", "512MiB", "rotate logs larger than this")
	keep := fs.Int("keep-hours", 24, "delete rotated logs older than this")
	rawDays := fs.Int("raw-days", 7, "delete raw/<day> dirs older than this")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	ms, err := logs.ParseSize(*maxSize)
	if err != nil {
		return fail("%v", err)
	}
	cfg, err := config.Load(env.ConfigDir())
	if err != nil {
		return fail("%v", err)
	}
	eng, err := newEngine(cfg.Node)
	if err != nil {
		return fail("%v", err)
	}
	rep, err := logs.Rotate(filepath.Join(env.DataDir(), "logs"), filepath.Join(env.DataDir(), "raw"), eng,
		logs.Options{MaxSize: ms, KeepHours: *keep, RawDays: *rawDays, Now: time.Now(), ReopenAudit: func() error {
			old := apply.ReadAuditSlot(env.DataDir())
			if err := apply.WriteAuditSlot(env.DataDir(), old+1); err != nil {
				return err
			}
			if rc := doApply(env.ConfigDir(), false); rc != 0 {
				_ = apply.WriteAuditSlot(env.DataDir(), old)
				return fmt.Errorf("apply exit %d", rc)
			}
			return nil
		}})
	if rep != nil {
		for _, r := range rep.Rotated {
			fmt.Println("rotated", r)
		}
		for _, d := range rep.Deleted {
			fmt.Println("deleted", d)
		}
	}
	if err != nil {
		return fail("%v", err)
	}
	return 0
}

// querier returns the ClickHouse client, or clickhouse local over raw JSONL when raw != "".
func querier(raw string) ch.Querier {
	if raw != "" {
		return &ch.Raw{Dir: raw}
	}
	return ch.FromEnv(env.ConfigDir())
}

func cmdLogsQuery(sub string, args []string) int {
	fs := flag.NewFlagSet("logs "+sub, flag.ContinueOnError)
	ff := logs.AddFilterFlags(fs, "1h", 100)
	format := fs.String("format", "table", "table|json")
	raw := fs.String("raw", "", "query raw JSONL under DIR offline (clickhouse local) instead of ClickHouse")
	interval := fs.Duration("interval", 2*time.Second, "tail poll interval")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := ff.Finish(time.Now())
	if err != nil {
		return fail("%v", err)
	}
	if *format != "table" && *format != "json" {
		return fail("--format %q not in table|json", *format)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	q := querier(*raw)
	if sub == "tail" {
		if err := logs.Tail(ctx, q, f, *format, *interval, os.Stdout); err != nil {
			return fail("%v", err)
		}
		return 0
	}
	rows, err := logs.Search(ctx, q, f)
	if err != nil {
		return fail("%v", err)
	}
	if err := logs.WriteRows(os.Stdout, rows, *format, true); err != nil {
		return fail("%v", err)
	}
	return 0
}

func cmdLogsShow(args []string) int {
	fs := flag.NewFlagSet("logs show", flag.ContinueOnError)
	format := fs.String("format", "table", "table|json")
	raw := fs.String("raw", "", "query raw JSONL under DIR offline")
	rid := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		rid, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if rid == "" && fs.NArg() == 1 {
		rid = fs.Arg(0)
	}
	if rid == "" {
		return fail("usage: wafctl logs show <request_id> [--format table|json] [--raw DIR]")
	}
	if err := logs.Show(context.Background(), querier(*raw), rid, *format, os.Stdout); err != nil {
		return fail("%v", err)
	}
	return 0
}
