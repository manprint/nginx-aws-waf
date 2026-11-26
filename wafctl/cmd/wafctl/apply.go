package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"nginxawswaf/wafctl/internal/apply"
	"nginxawswaf/wafctl/internal/docker"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/render"
)

func doApply(dir string, dry bool) int {
	p, rc := prepare(dir)
	if rc != 0 {
		return rc
	}
	home, err := env.Home()
	if err != nil {
		return fail("%v", err)
	}
	eng, err := docker.NewCompose(home, p.Cfg.Node.Network, env.DataDir())
	if err != nil {
		return fail("%v", err)
	}
	rev, err := apply.Apply(p, eng, filepath.Join(env.DataDir(), "runtime"), apply.Options{DryRun: dry,
		Log: func(s string) { fmt.Fprintln(os.Stderr, s) }})
	if err != nil {
		return fail("%v", err)
	}
	if dry {
		fmt.Printf("dry-run ok %s\n", rev)
	} else {
		fmt.Printf("applied %s\n", rev)
	}
	return 0
}

func cmdApply(args []string) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	dir := fs.String("config", env.ConfigDir(), "node config directory")
	dry := fs.Bool("dry-run", false, "stop after nginx -t")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return doApply(*dir, *dry)
}

func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	dir := fs.String("config", env.ConfigDir(), "node config directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	p, rc := prepare(*dir)
	if rc != 0 {
		return rc
	}
	tmp, err := os.MkdirTemp("", "wafctl-diff-")
	if err != nil {
		return fail("%v", err)
	}
	defer os.RemoveAll(tmp)
	newDir := filepath.Join(tmp, "new")
	if err := render.WriteTree(p.Out, filepath.Join(tmp, "raw")); err != nil {
		return fail("%v", err)
	}
	cur := filepath.Join(env.DataDir(), "runtime", "current")
	curDir := filepath.Join(tmp, "current")
	if _, err := os.Stat(cur); err != nil {
		_ = os.MkdirAll(curDir, 0o755)
	} else if err := apply.CopyNormalized(cur+"/", curDir); err != nil {
		return fail("%v", err)
	}
	if err := apply.CopyNormalized(filepath.Join(tmp, "raw"), newDir); err != nil {
		return fail("%v", err)
	}
	cmd := exec.Command("diff", "-ru", "--exclude=meta.json", "current", "new")
	cmd.Dir = tmp
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return 1
		}
		return fail("diff: %v", err)
	}
	return 0
}
