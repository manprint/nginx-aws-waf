package main

import (
	"flag"
	"os"

	"nginxawswaf/wafctl/internal/bypass"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/explain"
)

func cmdExplain(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	dir := fs.String("config", env.ConfigDir(), "node config directory")
	format := fs.String("format", "table", "table|json")
	site := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		site, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if site == "" && fs.NArg() > 0 {
		site = fs.Arg(0)
	}
	if site == "" {
		return fail("usage: wafctl explain <site> [--format table|json]")
	}
	cat, err := loadCatalog()
	if err != nil {
		return fail("%v", err)
	}
	cfg, err := config.Load(*dir)
	if err != nil {
		return fail("%v", err)
	}
	st, err := bypass.Load(bypass.Path(*dir))
	if err != nil {
		return fail("%v", err)
	}
	e, err := config.Effective(cfg, site, cat, st.Active(nowFn())[site])
	if err != nil {
		return fail("%v", err)
	}
	if err := explain.Write(os.Stdout, explain.Build(e, cat), *format); err != nil {
		return fail("%v", err)
	}
	return 0
}
