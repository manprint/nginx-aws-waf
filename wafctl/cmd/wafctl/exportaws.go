package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"nginxawswaf/wafctl/internal/awsexport"
	"nginxawswaf/wafctl/internal/config"
	"nginxawswaf/wafctl/internal/env"
)

const exportUsage = "usage: wafctl export-aws --site S [--format json|terraform] [--allow-lossy] [--region R] [--account N] [--acl-only] [-o FILE]"

func cmdExportAWS(args []string) int {
	fs := flag.NewFlagSet("export-aws", flag.ContinueOnError)
	dir := fs.String("config", env.ConfigDir(), "node config directory")
	site := fs.String("site", "", "site id")
	format := fs.String("format", "json", "json|terraform")
	lossy := fs.Bool("allow-lossy", false, "export anyway, omitting the nginx-only features (listed in lossy)")
	region := fs.String("region", "eu-central-1", "AWS region (IP set ARNs, Terraform provider)")
	account := fs.String("account", "000000000000", "AWS account id (IP set ARNs)")
	aclOnly := fs.Bool("acl-only", false, "json: write only the CreateWebACL input (for aws wafv2 create-web-acl --cli-input-json)")
	out := fs.String("o", "-", "output file (- = stdout)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *site == "" || (*format != "json" && *format != "terraform") {
		return fail("%s", exportUsage)
	}
	cat, err := loadCatalog()
	if err != nil {
		return fail("%v", err)
	}
	cfg, err := config.Load(*dir)
	if err != nil {
		return fail("%v", err)
	}
	for _, is := range config.Validate(cfg, cat) {
		if is.Severity == "error" {
			return fail("config invalid: %s: %s: %s (run wafctl validate)", is.File, is.Path, is.Msg)
		}
	}
	e, err := config.Effective(cfg, *site, cat, false)
	if err != nil {
		return fail("%v", err)
	}
	doc, err := awsexport.Build(e, cat, awsexport.Options{AllowLossy: *lossy, Region: *region, Account: *account})
	var le *awsexport.LossyError
	if errors.As(err, &le) {
		fmt.Fprintf(os.Stderr, "wafctl: site %s is not aws-compatible:\n", le.Site)
		for _, r := range le.Reasons {
			fmt.Fprintf(os.Stderr, "  - %s\n", r)
		}
		fmt.Fprintln(os.Stderr, "use --allow-lossy to export without these features")
		return 2
	}
	if err != nil {
		return fail("%v", err)
	}
	var b []byte
	if *format == "terraform" {
		b, err = awsexport.HCL(doc, *region)
	} else {
		b, err = awsexport.JSON(doc, *aclOnly)
	}
	if err != nil {
		return fail("%v", err)
	}
	for _, r := range doc.Lossy {
		fmt.Fprintf(os.Stderr, "warning: lossy: %s (omitted)\n", r)
	}
	if *out == "-" {
		os.Stdout.Write(b)
		return 0
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return fail("%v", err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d rules, %d ip sets)\n", *out, len(doc.WebACL["Rules"].([]awsexport.M)), len(doc.IPSets))
	return 0
}
