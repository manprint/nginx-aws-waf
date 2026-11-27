package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"nginxawswaf/wafctl/internal/central"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
)

func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	dir := fs.String("config", env.ConfigDir(), "node config directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cat, err := loadCatalog()
	if err != nil {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		return 2
	}
	cfg, err := config.Load(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		return 2
	}
	issues := config.Validate(cfg, cat)
	for _, i := range issues {
		fmt.Println(i.String())
	}
	for _, s := range cfg.Sites {
		e, err := config.Effective(cfg, s.SiteID, cat, false)
		if err != nil {
			continue // already reported by Validate
		}
		if r := config.Compat(e, cat); len(r) > 0 {
			fmt.Printf("site %s: nginx-only (%s)\n", s.SiteID, strings.Join(r, "; "))
		} else {
			fmt.Printf("site %s: aws-compatible\n", s.SiteID)
		}
	}
	bad := config.HasErrors(issues)
	if r := cfg.Node.Role; r == "central" || r == "all-in-one" {
		c, err := central.Load(*dir)
		if err != nil {
			fmt.Println(err)
			bad = true
		} else {
			errs, warns := c.Validate(*dir)
			for _, e := range errs {
				fmt.Printf("%s: %s\n", central.FileName, e)
			}
			for _, w := range warns {
				fmt.Printf("%s: warning: %s\n", central.FileName, w)
			}
			bad = bad || len(errs) > 0
		}
	}
	if bad {
		return 2
	}
	return 0
}
