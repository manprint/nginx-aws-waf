package main

import (
	"flag"
	"fmt"
	"os"

	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/secrets"
)

func cmdSecrets(args []string) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(os.Stderr, "usage: wafctl secrets init [--force]")
		return 2
	}
	fs := flag.NewFlagSet("secrets init", flag.ContinueOnError)
	force := fs.Bool("force", false, "regenerate all values (services must be re-created)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	p := env.SecretsFile()
	w, err := secrets.Init(p, *force)
	if err != nil {
		return fail("%v", err)
	}
	if len(w) == 0 {
		fmt.Printf("%s: up to date\n", p)
	} else {
		fmt.Printf("%s: wrote %d keys\n", p, len(w))
	}
	return 0
}
