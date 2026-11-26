package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"nginxawswaf/wafctl/internal/apply"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/docker"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/logs"
)

func cmdLogs(args []string) int {
	if len(args) == 0 || args[0] != "rotate" {
		return fail("usage: wafctl logs rotate [--max-size 512MiB] [--keep-hours 24] [--raw-days 7]")
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
	home, err := env.Home()
	if err != nil {
		return fail("%v", err)
	}
	eng, err := docker.NewCompose(home, cfg.Node.Network, env.DataDir())
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
