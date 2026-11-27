package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"nginxawswaf/wafctl/internal/central"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/secrets"
)

func grafanaAPI() (*central.GrafanaAPI, error) {
	pw := os.Getenv("GF_ADMIN_PASSWORD")
	if pw == "" {
		m, err := secrets.Load(env.SecretsFile())
		if err != nil {
			return nil, fmt.Errorf("GF_ADMIN_PASSWORD: %v (run wafctl secrets init)", err)
		}
		pw = m["GF_ADMIN_PASSWORD"]
	}
	url := os.Getenv("WAF_GRAFANA_URL")
	if url == "" {
		url = "http://127.0.0.1:3000"
	}
	return &central.GrafanaAPI{URL: url, User: "admin", Password: pw}, nil
}

func cmdGrafana(args []string) int {
	usage := "usage: wafctl grafana user add <login> [--name N] [--email E] [--role Admin|Editor|Viewer] [--password-stdin]\n       wafctl grafana user list"
	if len(args) < 2 || args[0] != "user" {
		return fail("%s", usage)
	}
	g, err := grafanaAPI()
	if err != nil {
		return fail("%v", err)
	}
	ctx := context.Background()
	switch args[1] {
	case "list":
		us, err := g.Users(ctx)
		if err != nil {
			return fail("%v", err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tLOGIN\tNAME\tEMAIL\tROLE")
		for _, u := range us {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", u.ID, u.Login, u.Name, u.Email, u.Role)
		}
		tw.Flush()
		return 0
	case "add":
		rest := args[2:]
		login := ""
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			login, rest = rest[0], rest[1:]
		}
		fs := flag.NewFlagSet("grafana user add", flag.ContinueOnError)
		name := fs.String("name", "", "display name (default: login)")
		email := fs.String("email", "", "email (default: <login>@localhost)")
		role := fs.String("role", "Viewer", "Admin|Editor|Viewer")
		stdin := fs.Bool("password-stdin", false, "read the password from stdin (else a random one is printed once)")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if login == "" && fs.NArg() == 1 {
			login = fs.Arg(0)
		}
		if login == "" {
			return fail("%s", usage)
		}
		if !central.ValidRole(*role) {
			return fail("--role %q not in Admin|Editor|Viewer", *role)
		}
		pw, generated := "", false
		if *stdin {
			sc := bufio.NewScanner(os.Stdin)
			if sc.Scan() {
				pw = strings.TrimRight(sc.Text(), "\r\n")
			}
			if len(pw) < 8 {
				return fail("password from stdin must be at least 8 characters")
			}
		} else {
			if pw, err = central.RandomPassword(20); err != nil {
				return fail("%v", err)
			}
			generated = true
		}
		id, err := g.AddUser(ctx, login, *name, *email, *role, pw)
		if err != nil {
			return fail("%v", err)
		}
		fmt.Printf("user %s created (id %d, role %s)\n", login, id, *role)
		if generated {
			fmt.Printf("password: %s\n(shown once: store it now)\n", pw)
		}
		return 0
	}
	return fail("%s", usage)
}
