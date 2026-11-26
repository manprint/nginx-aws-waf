# Plan 001 — history

## 0.1 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- Base: unborn HEAD + tree 6814df79. G-BASE: `bash -n scripts/*.sh` OK; 5 untracked baseline paths.
- Changes: `.gitignore` (+build/runtime ignores), NEW `Makefile` (help/fetch/wafctl/test-unit), NEW `scripts/lab-env.sh`.
- G-U01: `make help` OK; `git check-ignore build/x .run/x a.pem | wc -l` = 3; 46 files staged (≥ 30); no secret paths staged.
- Plan correction (rev 1, locator-level): `git check-ignore -q` accepts one path only → gate now counts 3 lines (phase_01 Done, STATE G-U01). Not weaker.
- self-review: diff limited to owned files; docs/aws, data/, scripts/ content unchanged except NEW lab-env.sh.

## 0.2 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW: waf/catalog/rules.yaml (snippet minus line 1, diff empty), waf/data/{bad-bots 79, ec2-metadata 11, lfi-targets 11} lines, no comments/blank; waf/static/403.html + 500.html (CRLF via printf); waf/README.md.
- G-U02 passed. self-review: catalog byte-identical; pages CRLF verified with od.

## 0.3 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW wafctl module (go 1.27.3, yaml.v3 v3.0.1): internal/{version,env,catalog}, cmd/wafctl/{main.go,catalog.go} (`version`, `catalog list|show`).
- G-U03: go vet clean; TestCAT1_, TestCAT2_ PASS (2/2); `catalog list | wc -l` = 56; unknown command → exit 2.
- Additions within contract: `env.CatalogPath()`, `Catalog.Rules()`, duplicate group key check. self-review OK.

## 0.4 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW wafctl/internal/config/{types,load,merge,config_test}.go + testdata; profiles/{aws-default,shadow,strict}.yaml.
- Signature: `Effective(cfg, siteID, cat, bypass bool)` (bypass param per contract). Node defaults: role node, network host, listen host→80/443 bridge→8080/8443, ipv6 true, audit all, central 6000/6001, retention 7d/24h. Added `Config.Site`, `Config.SiteIndex` (sorted site_id, D23), `Cond.Kinds()`.
- Effective groups sorted in catalog order (unknown names last); unset Enabled → !optional. Profiles: config dir wins over $WAF_HOME; name must equal file name.
- G-U04: TestCFG1_..TestCFG7_ PASS (7/7); go vet clean. self-review OK.

## 0.5 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW wafctl/internal/config/{validate,compat,validate_test}.go, cmd/wafctl/validate.go; lab/config/{node.yaml,sites/demo.yaml}. Load now defaults `tls.mode` to off.
- Validation: rules 1–9 implemented; extra checks within contract: default_site must exist, realtime path/servers, StrMatch exactly-one-of + name rules. Optional group listed without enabled → warning.
- G-U05: TestVAL1_..TestVAL9_ + TestCMP1_ → 55 PASS lines (incl. subtests, ≥ 15); `wafctl validate --config lab/config` exit 0, prints `site demo: nginx-only (client_ip.source=xff)`.
- self-review OK.
