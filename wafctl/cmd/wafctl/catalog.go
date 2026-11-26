package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"nginxawswaf/wafctl/internal/catalog"
	"nginxawswaf/wafctl/internal/env"
	"nginxawswaf/wafctl/internal/version"
)

func cmdVersion([]string) int {
	fmt.Println("wafctl", version.Version)
	return 0
}

func loadCatalog() (*catalog.Catalog, error) {
	p, err := env.CatalogPath()
	if err != nil {
		return nil, err
	}
	return catalog.Load(p)
}

func cmdCatalog(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: wafctl catalog list [--group KEY] [--format table|json] | show <name|id>")
		return 2
	}
	cat, err := loadCatalog()
	if err != nil {
		return fail("%v", err)
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("catalog list", flag.ContinueOnError)
		group := fs.String("group", "", "group key")
		format := fs.String("format", "table", "table|json")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		var rules []*catalog.Rule
		for _, r := range cat.Rules() {
			if *group == "" || r.Group.Key == *group {
				rules = append(rules, r)
			}
		}
		switch *format {
		case "json":
			type row struct {
				ID            int    `json:"id"`
				Group         string `json:"group"`
				Name          string `json:"name"`
				Label         string `json:"label"`
				DefaultAction string `json:"default_action"`
				Fidelity      string `json:"fidelity"`
				Detectors     int    `json:"detectors"`
			}
			out := []row{}
			for _, r := range rules {
				out = append(out, row{r.ID, r.Group.Key, r.Name, catalog.FullLabel(r), r.DefaultAction, r.Fidelity, len(r.Detectors)})
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(out)
		case "table":
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tGROUP\tNAME\tDEFAULT\tFIDELITY\tDETECTORS")
			for _, r := range rules {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\n", r.ID, r.Group.Key, r.Name, r.DefaultAction, r.Fidelity, len(r.Detectors))
			}
			tw.Flush()
		default:
			return fail("unknown format %q", *format)
		}
		return 0
	case "show":
		if len(args) != 2 {
			return fail("usage: wafctl catalog show <name|id>")
		}
		var r *catalog.Rule
		if id, err := strconv.Atoi(args[1]); err == nil {
			r = cat.RuleByID(id)
		} else {
			for _, x := range cat.Rules() {
				if x.Name == args[1] {
					r = x
					break
				}
			}
		}
		if r == nil {
			return fail("rule %q not found", args[1])
		}
		fmt.Printf("# group: %s (%s)\n# label: %s\n", r.Group.Name, r.Group.Key, catalog.FullLabel(r))
		b, _ := yaml.Marshal(r)
		os.Stdout.Write(b)
		return 0
	}
	return fail("unknown catalog subcommand %q", args[0])
}
