package config

import (
	"nginxawswaf/wafctl/internal/catalog"
)

// AWSBodyLimits are the body inspection sizes an ALB association accepts.
var AWSBodyLimits = []int{8192, 16384, 32768, 49152, 65536}

// Compat returns why a site cannot be reproduced on AWS WAF; empty = aws-compatible.
func Compat(e *EffectiveSite, _ *catalog.Catalog) []string {
	var r []string
	w := &e.WAF
	ok := false
	for _, b := range AWSBodyLimits {
		if w.BodyLimit == b {
			ok = true
		}
	}
	if !ok {
		r = append(r, "body_limit not in {8192,16384,32768,49152,65536}")
	}
	if w.ClientIP.Source == "xff" {
		r = append(r, "client_ip.source=xff")
	}
	if w.Fail.PCRELimit == "block" {
		r = append(r, "fail.pcre_limit=block")
	}
	if w.Fail.BodyError == "closed" || w.Fail.BodyError == "block" {
		r = append(r, "fail.body_error="+w.Fail.BodyError)
	}
	if len(w.PathOverrides) > 0 {
		r = append(r, "path_overrides")
	}
	if e.Node != nil && e.Node.Audit.Scope == "relevant" {
		r = append(r, "audit.scope=relevant")
	}
	if w.BlockPage != "aws" {
		r = append(r, "block_page="+w.BlockPage)
	}
	return r
}
