package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/testrun"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func newRunner(fs *flag.FlagSet) (*testrun.Runner, *string, *string) {
	r := &testrun.Runner{}
	fs.StringVar(&r.Target, "target", "http://127.0.0.1:8080", "node URL")
	fs.StringVar(&r.AuditPath, "audit", filepath.Join(env.DataDir(), "logs", "audit.log"), "audit log path")
	dir := fs.String("config", env.ConfigDir(), "node config directory")
	format := fs.String("format", "text", "text|json")
	return r, dir, format
}

func setupRunner(r *testrun.Runner, dir string) error {
	cfg, err := config.Load(dir)
	if err != nil {
		return err
	}
	r.Hosts = map[string]string{}
	for _, s := range cfg.Sites {
		if len(s.ServerNames) > 0 {
			r.Hosts[s.SiteID] = s.ServerNames[0]
		}
	}
	r.IndexPath = filepath.Join(env.DataDir(), "runtime", "current", "rules-index.json")
	r.ListsDir = filepath.Join(env.DataDir(), "lists")
	return nil
}

func cmdTest(args []string) int {
	if len(args) == 0 {
		return fail("usage: wafctl test run --suite DIR|FILE | test request --site S ...")
	}
	switch args[0] {
	case "run":
		fs := flag.NewFlagSet("test run", flag.ContinueOnError)
		r, dir, format := newRunner(fs)
		suite := fs.String("suite", "tests/corpus", "corpus dir or file")
		filter := fs.String("filter", "", "only case ids containing S")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		cases, err := testrun.LoadSuite(*suite)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wafctl:", err)
			return 2
		}
		if *filter != "" {
			var f []testrun.Case
			for _, c := range cases {
				if strings.Contains(c.ID, *filter) {
					f = append(f, c)
				}
			}
			cases = f
		}
		if err := setupRunner(r, *dir); err != nil {
			return fail("%v", err)
		}
		res, err := r.Run(cases)
		if err != nil {
			return fail("%v", err)
		}
		if testrun.Print(os.Stdout, res, *format) > 0 || len(res) == 0 {
			return 1
		}
		return 0
	case "request":
		fs := flag.NewFlagSet("test request", flag.ContinueOnError)
		r, dir, format := newRunner(fs)
		c := testrun.Case{ID: "adhoc", Expect: testrun.Expect{}}
		fs.StringVar(&c.Site, "site", "", "site id")
		fs.StringVar(&c.Request.Method, "method", "GET", "method")
		fs.StringVar(&c.Request.Path, "path", "/", "raw path")
		fs.StringVar(&c.Request.Body, "data", "", "body")
		fs.StringVar(&c.Request.XFF, "xff", "198.51.100.10", "X-Forwarded-For")
		var hs multiFlag
		fs.Var(&hs, "H", "header 'K: V' (repeatable)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if c.Site == "" {
			fmt.Fprintln(os.Stderr, "wafctl: --site is required")
			return 2
		}
		c.Request.Headers = map[string]string{}
		for _, h := range hs {
			k, v, _ := strings.Cut(h, ":")
			c.Request.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		if err := setupRunner(r, *dir); err != nil {
			return fail("%v", err)
		}
		res, err := r.Run([]testrun.Case{c})
		if err != nil {
			return fail("%v", err)
		}
		x := res[0]
		if *format == "json" {
			testrun.Print(os.Stdout, res, "json")
			return 0
		}
		if x.Summary == "" {
			return fail("%s", x.Error)
		}
		fmt.Printf("status=%d term=%s mode=%s\nsummary: %s\nmatches: %s\n", x.Status, x.Term, x.Mode, x.Summary, strings.Join(x.Matches, ", "))
		return 0
	}
	return fail("unknown test subcommand %q", args[0])
}
