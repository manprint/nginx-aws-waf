package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"nginxawswaf/wafctl/internal/apply"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/render"
)

// prepare runs apply.Prepare and prints issues/warnings; rc != 0 on failure (2 = validation).
func prepare(dir string) (*apply.Prepared, int) {
	p, err := apply.Prepare(dir, time.Now())
	if p != nil {
		for _, i := range p.Issues {
			fmt.Fprintln(os.Stderr, i.String())
		}
		for _, w := range p.Warnings {
			fmt.Fprintln(os.Stderr, "warning:", w)
		}
	}
	if errors.Is(err, apply.ErrInvalid) {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		return nil, 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		return nil, 2
	}
	return p, 0
}

func cmdRender(args []string) int {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	dir := fs.String("config", env.ConfigDir(), "node config directory")
	outDir := fs.String("out", "", "output dir (default $WAF_DATA_DIR/runtime/<rev>)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	p, rc := prepare(*dir)
	if rc != 0 {
		return rc
	}
	d := *outDir
	if d == "" {
		d = filepath.Join(env.DataDir(), "runtime", p.Out.Rev)
	}
	if err := render.WriteTree(p.Out, d); err != nil {
		return fail("%v", err)
	}
	fmt.Println(d)
	return 0
}
