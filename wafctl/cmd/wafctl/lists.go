package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/lists"
)

const listsUsage = "usage: wafctl lists update [--force] [--no-apply] [--script PATH] [--config DIR]"

func cmdLists(args []string) int {
	if len(args) == 0 || args[0] != "update" {
		return fail("%s", listsUsage)
	}
	fs := flag.NewFlagSet("lists update", flag.ContinueOnError)
	dir := fs.String("config", env.ConfigDir(), "node config directory")
	force := fs.Bool("force", false, "replace lists even when the new one has < 50% of the old entries")
	noApply := fs.Bool("no-apply", false, "do not run wafctl apply after a change")
	script := fs.String("script", "", "fetch script (default $WAF_HOME/scripts/fetch-ip-lists.sh)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *script == "" {
		h, err := env.Home()
		if err != nil {
			return fail("%v", err)
		}
		*script = filepath.Join(h, "scripts", "fetch-ip-lists.sh")
	}
	res, changed, err := lists.Update(lists.Options{
		ListsDir: filepath.Join(env.DataDir(), "lists"),
		Force:    *force,
		Fetch:    lists.ScriptFetcher(*script, os.Stderr),
	})
	if err != nil {
		return fail("lists update: %v (no list was replaced)", err)
	}
	lists.Table(os.Stdout, res)
	if !changed {
		fmt.Println("no list changed: apply skipped")
		return 0
	}
	if *noApply {
		fmt.Println("lists changed: run wafctl apply to reload")
		return 0
	}
	fmt.Println("lists changed: applying")
	return doApply(*dir, false)
}
