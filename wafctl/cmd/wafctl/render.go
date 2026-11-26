package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/render"
	"nginxawswaf/wafctl/internal/version"
)

// renderConfig loads, validates and renders; validation errors are printed and returned as exit 2.
func renderConfig(dir string, bypass map[string]bool) (*render.Output, int) {
	cat, err := loadCatalog()
	if err != nil {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		return nil, 2
	}
	cfg, err := config.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		return nil, 2
	}
	issues := config.Validate(cfg, cat)
	for _, i := range issues {
		fmt.Fprintln(os.Stderr, i.String())
	}
	if config.HasErrors(issues) {
		return nil, 2
	}
	created, err := render.EnsureLists(cat, filepath.Join(env.DataDir(), "lists"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		return nil, 1
	}
	for _, n := range created {
		fmt.Fprintf(os.Stderr, "warning: list %s missing; created placeholder in %s\n", n, filepath.Join(env.DataDir(), "lists"))
	}
	out, err := render.Render(cfg, cat, bypass, render.Options{Version: version.Version})
	if err != nil {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		return nil, 1
	}
	return out, 0
}

func cmdRender(args []string) int {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	dir := fs.String("config", env.ConfigDir(), "node config directory")
	outDir := fs.String("out", "", "output dir (default $WAF_DATA_DIR/runtime/<rev>)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	out, rc := renderConfig(*dir, nil)
	if rc != 0 {
		return rc
	}
	d := *outDir
	if d == "" {
		d = filepath.Join(env.DataDir(), "runtime", out.Rev)
	}
	if err := render.WriteTree(out, d); err != nil {
		return fail("%v", err)
	}
	fmt.Println(d)
	return 0
}
