// Package logs rotates the node logs and prunes raw JSONL directories.
package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Execer runs a command in a compose service.
type Execer interface {
	Exec(svc string, args ...string) (string, error)
}

// Options for Rotate.
type Options struct {
	MaxSize   int64
	KeepHours int
	RawDays   int
	Now       time.Time
	// ReopenAudit makes ModSecurity open a fresh audit log (flip the slot and apply);
	// called after access/error were reopened, only when audit.log was rotated.
	ReopenAudit func() error
}

// Report lists what Rotate did.
type Report struct {
	Rotated []string
	Deleted []string
}

// Names are the rotated log files.
var Names = []string{"access.log", "audit.log", "error.log"}

const stampFmt = "20060102T150405Z"

var reRotated = regexp.MustCompile(`^(access|audit|error)\.log\.(\d{8}T\d{6}Z)$`)
var reDay = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// ParseSize parses 512MiB, 1GiB, 10KiB, 100 (bytes), also KB/MB/GB as binary units.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suf) {
			s, mult = strings.TrimSuffix(s, u.suf), u.m
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n * mult, nil
}

// Rotate renames oversized logs, makes nginx reopen them, prunes old rotated files and raw days.
func Rotate(logsDir, rawDir string, eng Execer, o Options) (*Report, error) {
	now := o.Now.UTC()
	rep := &Report{}
	for _, n := range Names {
		p := filepath.Join(logsDir, n)
		st, err := os.Stat(p)
		if err != nil || st.Size() <= o.MaxSize {
			continue
		}
		dst := p + "." + now.Format(stampFmt)
		if err := os.Rename(p, dst); err != nil {
			return rep, err
		}
		rep.Rotated = append(rep.Rotated, filepath.Base(dst))
	}
	if len(rep.Rotated) > 0 && eng != nil {
		if out, err := eng.Exec("waf", "nginx", "-s", "reopen"); err != nil {
			return rep, fmt.Errorf("nginx -s reopen: %v\n%s", err, out)
		}
		for _, r := range rep.Rotated {
			if strings.HasPrefix(r, "audit.log.") && o.ReopenAudit != nil {
				if err := o.ReopenAudit(); err != nil {
					return rep, fmt.Errorf("reopen audit log: %w", err)
				}
			}
		}
	}
	ents, _ := os.ReadDir(logsDir)
	for _, e := range ents {
		m := reRotated.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		t, err := time.Parse(stampFmt, m[2])
		if err != nil || now.Sub(t) <= time.Duration(o.KeepHours)*time.Hour {
			continue
		}
		if err := os.Remove(filepath.Join(logsDir, e.Name())); err != nil {
			return rep, err
		}
		rep.Deleted = append(rep.Deleted, e.Name())
	}
	cutoff := now.AddDate(0, 0, -o.RawDays).Format("2006-01-02")
	days, _ := os.ReadDir(rawDir)
	for _, d := range days {
		if !d.IsDir() || !reDay.MatchString(d.Name()) || d.Name() >= cutoff {
			continue
		}
		if err := os.RemoveAll(filepath.Join(rawDir, d.Name())); err != nil {
			return rep, err
		}
		rep.Deleted = append(rep.Deleted, "raw/"+d.Name())
	}
	return rep, nil
}
