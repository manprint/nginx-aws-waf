package main

import (
	"flag"
	"fmt"
	"nginxawswaf/wafctl/internal/pki"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nginxawswaf/wafctl/internal/apply"
	"nginxawswaf/wafctl/internal/central"
	"nginxawswaf/wafctl/internal/docker"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/render"
)

func doApply(dir string, dry bool) int {
	p, rc := prepare(dir)
	if rc != 0 {
		return rc
	}
	eng, err := newEngine(p.Cfg.Node)
	if err != nil {
		return fail("%v", err)
	}
	role := p.Cfg.Node.Role
	var changed []string
	if role == "central" || role == "all-in-one" {
		// central files must exist before compose up (bind mounts)
		if changed, err = renderCentral(dir); err != nil {
			return fail("%v", err)
		}
		if role == "central" {
			if dry {
				fmt.Println("dry-run ok (central)")
				return 0
			}
			return upCentral(eng, changed)
		}
	}
	// mount source of the node client cert (vector); created here so docker does not create it as root
	if err := os.MkdirAll(filepath.Join(env.DataDir(), "certs", "_node"), 0o700); err != nil {
		return fail("%v", err)
	}
	rev, err := apply.Apply(p, eng, filepath.Join(env.DataDir(), "runtime"), apply.Options{DryRun: dry,
		Log: func(s string) { fmt.Fprintln(os.Stderr, s) }})
	if err != nil {
		return fail("%v", err)
	}
	if dry {
		fmt.Printf("dry-run ok %s\n", rev)
		return 0
	}
	if role == "all-in-one" {
		if rc := upCentral(eng, changed); rc != 0 {
			return rc
		}
	}
	fmt.Printf("applied %s\n", rev)
	return 0
}

// renderCentral validates central.yaml and renders $WAF_CENTRAL_DIR; it returns the services whose files changed.
func renderCentral(configDir string) ([]string, error) {
	c, err := central.Load(configDir)
	if err != nil {
		return nil, err
	}
	errs, warns := c.Validate(configDir)
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "%s: warning: %s\n", central.FileName, w)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", central.FileName, strings.Join(errs, "; "))
	}
	changed, err := central.Render(c, configDir, env.CentralDir())
	if err != nil {
		return nil, err
	}
	st := pki.Open(env.PKIDir())
	if _, err := st.CACert(); err != nil {
		return nil, fmt.Errorf("central: the mTLS ingress needs the PKI: run wafctl pki init --name <name> (WAF_PKI_DIR=%s)", st.Dir)
	}
	ing, err := central.RenderIngress(c, st, env.CentralDir(), time.Now())
	if err != nil {
		return nil, fmt.Errorf("ingress: %w", err)
	}
	if ing {
		changed = append(changed, "ingress")
		sort.Strings(changed)
	}
	return changed, nil
}

// upCentral starts missing services (compose up -d is idempotent) and restarts the ones whose
// rendered files changed.
func upCentral(eng docker.Engine, changed []string) int {
	wasRunning := map[string]bool{}
	for _, s := range changed {
		wasRunning[s], _ = eng.Running(s)
	}
	if err := eng.Up(); err != nil {
		return fail("%v", err)
	}
	for _, s := range changed {
		if wasRunning[s] {
			if err := eng.Restart(s); err != nil {
				return fail("restart %s: %v", s, err)
			}
			fmt.Fprintf(os.Stderr, "%s restarted (rendered files changed)\n", s)
		}
	}
	return 0
}

func cmdCentral(args []string) int {
	if len(args) == 0 || args[0] != "render" {
		return fail("usage: wafctl central render [--config DIR]")
	}
	fs := flag.NewFlagSet("central render", flag.ContinueOnError)
	dir := fs.String("config", env.ConfigDir(), "config directory (central.yaml)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	changed, err := renderCentral(*dir)
	if err != nil {
		return fail("%v", err)
	}
	fmt.Printf("rendered %s (changed: %s)\n", env.CentralDir(), strings.Join(changed, ", "))
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
