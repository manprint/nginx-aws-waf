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

## 1.2 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW render/{conds.go,modsec_site.go,index.go,site_test.go}, testdata/config (5 fixtures mirroring the 1.4 lab sites), golden/sites/*.conf + main.conf. modsec.go wired (slots, scope-downs, site files, rules-index.json).
- config/validate.go: value rule (no quotes/newlines in exact/starts_with/contains; name no quotes/spaces) + max 6 conditions per match (tests added).
- Decisions within contract: path override values also pass through group override_action=count; path override setvars sorted by rule name; rev hash now covers rules-index.json (golden nosites regenerated).
- G-U12: TestR4_..TestR8_ PASS (5/5); G-NGXT --modsec-only on fixture render (main + 5 site files in servers): syntax ok / test successful.

## 1.3 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW render/{nginx.go,write.go,nginx_test.go}, templates/{nginx.conf.tmpl,site.conf.tmpl} (embed), golden/nginx/*; cmd/wafctl/render.go (`wafctl render [--config] [--out]`); ngx-test.sh full mode (mounts temp /var/log/waf, certs, runs as root like the runtime image).
- Render now also emits data/*.data, static/<site>/{403,500}.html (block_page from $config/pages), meta.json (after rev; excluded from hash). Options.Home (default env.Home()).
- Decisions: client_max_body_size default 10m, proxy timeouts default 60 s (unset upstream fields); realtime location omits the common proxy_read_timeout (duplicate directive) and uses 3600s.
- Plan correction: temp paths `/tmp/ngx_{body,proxy,fcgi,uwsgi,scgi}` instead of `/tmp/nginx/*` — nginx creates only the last path component, and compose `tmpfs: /tmp` hides any image-built /tmp/nginx.
- G-U13: TestR9_, TestR10_, TestR11_ PASS (3/3). G-NGXT full: fixture render OK; extra variant (tls redirect + realtime + rate count + self-signed cert) OK; `server … resolve` accepted (nginx 1.30.7).

## 1.4 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW waf/Dockerfile, deploy/compose/{node,node.host,node.bridge,lab-min}.yml, deploy/compose/lab/echo.conf, lab/config/sites/{allowlist,demo,shadow,strict,tuned}.yaml (= render fixtures), tests/e2e/{lib.sh,smoke.sh}; Makefile lab-min-up/down (exports WAF_HOME/CONFIG/DATA, `up --wait`).
- Fixes: echo service `healthcheck: {disable: true}` (base image HEALTHCHECK made it unhealthy); Dockerfile no longer creates /tmp/nginx (tmpfs); `/__waf/` location gains `etag off` (AWS block response has no ETag) — plan text updated.
- G-U14: smoke.sh ALL PASS (200; 403 body = waf/static/403.html; Server awselb/2.0; unknown host → curl 52; audit/access logs grow) + T-R12 checks (tuned POST 9000 B /web/dataset/call_kw → 200 count; /other → 403 via label custom rule).
- Note: re-running lab-min-up renders a new rev and moves `current` but does not reload nginx; reload belongs to `wafctl apply` (1.5).

## 1.5 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW internal/{docker,apply,bypass,explain}, cmd/wafctl/{apply,explain,bypass}.go (apply, diff, explain, bypass list|clear|expire|<site>), render cmd now via apply.Prepare (bypass state honored), deploy/systemd/wafctl-bypass-expire.{service,timer}, tests/e2e/apply.sh. Makefile: lab-min-up → `wafctl apply`, `WAF_COMPOSE_EXTRA ?= deploy/compose/lab-min.yml`. Render test hook WAF_TEST_INJECT=1.
- Plan correction: `nginx -s reload` is asynchronous (e2e saw the old config for ~1 s). nginx.conf gains `location = /__rev { return 200 "<R>"; }` on 127.0.0.1:8090; apply polls it via `exec wget` until it serves the new rev (15 s timeout). Phase_02 text updated.
- Decisions: Compose project from env WAF_COMPOSE_PROJECT (default waf; used by node2 in 5.x); diff normalizes revs with a regex on both trees.
- G-U15: TestA1_, TestA2_, TestB1_, TestB2_ PASS (4/4); apply.sh ALL PASS (10 checks); smoke still ALL PASS; prune keeps ≤ 5 revs + current.

## 1.6 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW internal/testrun/{corpus,run,audit,testrun_test}.go + testdata/audit-line.json (real line), cmd/wafctl/test.go (`test run`, `test request`), tests/corpus/{iprep,crs,kbi,sqli,anonip,engine}.yaml (62 cases), tests/README.md; Makefile `test-e2e`.
- Plan correction: Host-override cases cannot reach a site through the 444 default server → lab demo `server_names: [demo.lab.test, localhost, 127.0.0.1]`; IPv6 `[::1]` is rejected by the server-name rule, so the v6 variant became `kbi-host-loopback-v4` (Host `127.0.0.1:8080`). Phase_02 text updated.
- Extras beyond the minimum: iprep-recon (@list:), iprep-clean-v6, clean-post-form, sqli-clean, path-override in/out split.
- G-U16: TestT1_/T2_/T3_ PASS; `make test-e2e` → PASSED 62/62 (≥ 60); smoke.sh and apply.sh still ALL PASS.
