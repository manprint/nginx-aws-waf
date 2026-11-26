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

## P0 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- G-P0: `make wafctl test-unit` all ok (64 PASS lines incl. subtests); `wafctl validate --config lab/config` exit 0.
- G-SEC spot check: no key/pem/secrets tracked.
- README obligation: README untouched (rewritten in 1.9); resources table still accurate.
- Review (agent-1, self-review): catalog ↔ config integration consistent (group names from catalog, labels via RuleByLabel); invariants D3/D18/D19/I-8 held; tests discover > 0. Plan correction during phase: G-U01 check-ignore form.

## 1.1 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW wafctl/internal/render/{render.go,modsec.go,render_test.go}, testdata/nosites/node.yaml, golden/nosites/main.conf; scripts/ngx-test.sh (--modsec-only + full); Makefile `lists`.
- G-U11: TestR1_ (oracle vs reference-render.py, not skipped), TestR2_, TestR3_ PASS (3/3). G-NGXT --modsec-only: syntax ok, test successful (243 rules loaded).
- Plan corrections (rev 1):
  - `SecRequestBodyInMemoryLimit` removed: libmodsecurity 3.0.17 rejects it ("no longer supported"); nginx `client_body_buffer_size 128k` governs memory buffering.
  - audit.scope=relevant evaluator variant (helpers 1900890–1900892 + conditional SUMMARY) — the unconditional SUMMARY `auditlog` made RelevantOnly log every request. Probed: matching request logged with SUMMARY, non-matching not logged. Documented in phase_02 Local design; TestR3 asserts it.
  - Rev hash excludes meta.json (it carries render time and the rev itself; including it would make every render a new rev).
- Test helper: `WAF_DUMP_DIR=<dir> go test ./internal/render -run TestR2_` dumps the render for ngx-test.sh.
