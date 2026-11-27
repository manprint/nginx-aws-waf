// Package lists refreshes the IP reputation lists in $WAF_DATA_DIR/lists from
// scripts/fetch-ip-lists.sh, with a download-failure guard and IP/CIDR validation.
package lists

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Managed are the list files the fetch script produces and Update replaces.
// custom-reputation.txt (operator-owned) is never touched.
var Managed = []string{"AWSManagedIPReputationList.txt", "AWSManagedReconnaissanceList.txt", "AWSManagedIPDDoSList.txt", "AnonymousIPList.txt"}

// Placeholders are list files the rules reference but no feed produces: created empty (comment
// only) when missing so that nginx -t passes on a new node, never modified afterwards.
var Placeholders = map[string]string{
	"custom-reputation.txt":     "# custom-reputation.txt - operator-owned IPs/CIDRs treated as AWSManagedIPReputationList; never touched by wafctl lists update\n",
	"HostingProviderIPList.txt": "# HostingProviderIPList - no public equivalent feed (AnonymousIpList)\n",
}

// Result is one row of the update table.
type Result struct {
	List     string
	Old, New int    // non-comment lines
	Status   string // updated | unchanged | kept | new | created
}

// Options of Update.
type Options struct {
	ListsDir string                    // $WAF_DATA_DIR/lists
	Force    bool                      // skip the 50 % guard
	Fetch    func(outDir string) error // writes the new lists into outDir
}

// ScriptFetcher runs the fetch script with OUT=<outDir>, its output to w.
func ScriptFetcher(script string, w io.Writer) func(string) error {
	return func(out string) error {
		cmd := exec.Command(script)
		cmd.Env = append(os.Environ(), "OUT="+out)
		cmd.Stdout, cmd.Stderr = w, w
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", script, err)
		}
		return nil
	}
}

// entries reads the non-comment, non-empty lines of a list; invalid IP/CIDR → error file:line.
func entries(path string, validate bool) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if validate {
			if _, err := netip.ParsePrefix(l); err != nil {
				if _, err := netip.ParseAddr(l); err != nil {
					return nil, fmt.Errorf("%s:%d: %q is not an IP or CIDR", path, n, l)
				}
			}
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// Update fetches, guards, validates and installs the managed lists.
// changed reports whether any file in ListsDir was replaced (→ apply).
func Update(o Options) (res []Result, changed bool, err error) {
	tmp, err := os.MkdirTemp("", "wafctl-lists-")
	if err != nil {
		return nil, false, err
	}
	defer os.RemoveAll(tmp)
	if err := o.Fetch(tmp); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(o.ListsDir, 0o755); err != nil {
		return nil, false, err
	}
	type plan struct {
		r       Result
		install bool
	}
	var plans []plan
	// validate everything before installing anything
	for _, name := range Managed {
		src := filepath.Join(tmp, name)
		if _, err := os.Stat(src); err != nil {
			return nil, false, fmt.Errorf("fetch did not produce %s", name)
		}
		nw, err := entries(src, true)
		if err != nil {
			return nil, false, err
		}
		old, err := entries(filepath.Join(o.ListsDir, name), false)
		if err != nil {
			return nil, false, err
		}
		_, statErr := os.Stat(filepath.Join(o.ListsDir, name))
		p := plan{r: Result{List: name, Old: len(old), New: len(nw)}}
		switch {
		case os.IsNotExist(statErr):
			p.r.Status, p.install = "new", true
		case equal(old, nw):
			p.r.Status = "unchanged"
		case !o.Force && 2*len(nw) < len(old):
			p.r.Status = "kept" // < 50 %: probably a failed download
		default:
			p.r.Status, p.install = "updated", true
		}
		plans = append(plans, p)
	}
	for _, p := range plans {
		if p.install {
			if err := install(filepath.Join(tmp, p.r.List), filepath.Join(o.ListsDir, p.r.List)); err != nil {
				return nil, false, err
			}
			changed = true
		}
		res = append(res, p.r)
	}
	for _, name := range []string{"HostingProviderIPList.txt", "custom-reputation.txt"} {
		dst := filepath.Join(o.ListsDir, name)
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			continue
		}
		if err := os.WriteFile(dst, []byte(Placeholders[name]), 0o644); err != nil {
			return nil, false, err
		}
		res = append(res, Result{List: name, Status: "created"})
		changed = true
	}
	return res, changed, nil
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// install copies src to dst via a temp file in dst's directory + rename.
func install(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	t, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(t.Name())
	if _, err := io.Copy(t, bytes.NewReader(b)); err != nil {
		t.Close()
		return err
	}
	if err := t.Chmod(0o644); err != nil {
		t.Close()
		return err
	}
	if err := t.Close(); err != nil {
		return err
	}
	return os.Rename(t.Name(), dst)
}

// Table formats the results.
func Table(w io.Writer, res []Result) {
	fmt.Fprintf(w, "%-34s %8s %8s  %s\n", "LIST", "OLD", "NEW", "STATUS")
	for _, r := range res {
		fmt.Fprintf(w, "%-34s %8d %8d  %s\n", r.List, r.Old, r.New, r.Status)
	}
}
