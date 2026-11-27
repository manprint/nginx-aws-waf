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

## 1.7 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW deploy/vector/node.yaml (snippet minus ClickHouse sinks + raw_matches; `vector validate` OK), compose service `vector` (node.yml + host/bridge overrides), internal/logs/{rotate,rotate_test}.go, cmd/wafctl/logs.go (`logs rotate`), deploy/systemd/wafctl-logs.{service,timer}, tests/e2e/joinlog.sh. `test run --format json` now carries `run_id`. Makefile lab-min-up also runs `compose up -d --build --wait` after apply (so new services start when waf is already running).
- Fix: after a WAF block, nginx's error_page internal redirect turns `$request_method` into GET → access log/events said GET for blocked POSTs. nginx.conf gains `map $request $waf_method {...}` (method from the original request line) and the log format uses it. Phase_02 text updated.
- Failure-handling branch hit and resolved (autonomous, agent-1): after rename + `nginx -s reload`, ModSecurity kept writing the renamed audit file (libmodsecurity SharedFiles keyed by path string survive reloads). Probe: a reload with `SecAuditLog /var/log/waf//audit.log` opened a fresh file. Chosen fix: audit slot (state/audit-slot) toggled by rotate + apply; rejected `nginx -s stop` + up (downtime on every rotation of a busy node). Phase_02 rotate contract updated.
- joinlog.sh refinement (non-weakening): the "≥ 1 matches row per blocking case" check applies to blocks by a rule; a Default_Action block has no matched rule by definition (allowlist-other).
- G-U17: TestL0_ PASS; joinlog.sh ALL PASS (T-L1 62 events, fields, matches; T-L2 2000 events; rotate: new audit.log, old handle closed, joined event after rotation).

## 1.8 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW scripts/bench.sh, tests/bench/rpc.json (353 B, generated with the plan's one-liner), docs/performance.md.
- G-PERF: 3 runs, all exit 0. Median GET 6101 rps p99 2.32 ms; POST 5282 rps p99 2.75 ms (D29: ≥3500/≥3000, ≤5 ms). worker_processes 2, logs bind-mounted, Vector running.

## 1.9 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- `wafctl catalog list --format markdown` (internal/catalog/markdown.go) + TestCAT3_ (exact header, one row per rule).
- Docs (Italian): README rewritten (purpose, quickstart, directory map, links); rules-spec §2 = D23 map, generated CRS detector table, D7/D8/D16 recorded, §7 items 3–4 resolved, stale rows (fail mode, overrides) updated; NEW docs/config-reference.md, docs/tuning.md, docs/operations.md.
- Self-review against the D-table: D7 (raw path), D8 (body limits), D16 (logs), D19 (paths), D23 (IDs), fail mode/bypass/rotation behaviour checked against code (merge semantics, defaults, compat reasons, cert defaults).
- G-U19: TestCAT3_ 1 PASS; docs reviewed.

## P1 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- G-P1 from a stopped lab (`make lab-min-down` first): `make test-unit` (7 packages ok) && `make lab-min-up` && `make test-e2e` (PASSED 62/62) && smoke.sh, apply.sh, joinlog.sh (ALL PASS each) → rc 0. G-PERF: GET 6363 rps p99 1.80 ms, POST 5143 rps p99 3.15 ms, exit 0. G-NGXT full + --modsec-only on the lab render: syntax ok, test successful. TestR* 11 PASS, no SKIP.
- Review (agent-1, self-review): I-1 first-wins case; I-2 count-override (event action ALLOW, aws_default_action BLOCK = I-4); I-3 shadow event status 200, action ALLOW, shadow_action BLOCK; bypass e2e; I-5 T-A1 + apply.sh; I-6/I-7 T-L1 one event per case, `Z` timestamps; I-8 no secrets tracked. Integration render ↔ apply ↔ testrun ↔ Vector consistent (rules-index.json shared). Docs updated in 1.9 (README obligation met).
- Plan corrections during the phase (all recorded in unit entries, none weakening): SecRequestBodyInMemoryLimit removed; audit.scope=relevant variant; nginx temp paths; echo healthcheck; reload wait on /__rev; lab localhost aliases; $waf_method; audit-slot rotation.

## 2.1 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW deploy/compose/lab.yml (pg12/13/15/16, odoo12/14/16/18, mem_limit 1500m, no published ports), lab/config/sites/shop{12,14,16,18}.yaml, profiles/odoo-{common,12,14,16,18}.yaml (labels checked against `wafctl catalog list`), scripts/lab-init-odoo.sh, tests/e2e/lab-smoke.sh, internal/config/profiles_test.go (T-PRF1). node.bridge.yml: network alias `waf`. Makefile: lab-up / lab-down / lab-reset (FORCE=1), COMPOSE_LAB.
- Deviation (non-weakening): the odoo image entrypoint appends `--db_host $HOST …` after the command, overriding the plan's flags → services also get env HOST=pgNN/USER/PASSWORD.
- Init durations (S2, §6): odoo12 40 s, odoo14 30 s, odoo16 27 s, odoo18 42 s; `make lab-up` total 3 min 05 s. No OOM (Odoo RSS 330–450 MiB of 1.5 GiB); --workers=2 kept.
- G-U21: TestPRF1_ PASS; lab-smoke.sh ALL PASS (16 checks; realtime 200 on /longpolling/poll, 400 on GET /websocket without upgrade); corpus still PASSED 62/62.

## 2.2 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW internal/testrun/{retarget,retarget_test}.go; `test run` flags --filter-site, --retarget, --exceptions; Makefile `test-odoo`; tests/odoo-exceptions.yaml; tests/README section.
- Exceptions (self-review, all justified, none weakens a block): (a) crs-size-body, -chunked, crs-rfi-body, crs-xss-body, crs-xss-multipart → still 403, terminating rule is the odoo-common label rule (path "/" is outside RPC paths) with the managed rule in `matches`; (b) clean-get 303 / clean-post-form 400 = Odoo's own answers after WAF Default_Action; (c) body-limit-8k on /web/dataset/call_kw → allowed: SizeRestrictions_BODY counted by design (D27) and the XSS after 8 KB is not inspected — same as AWS with an 8 KB limit; Odoo answers 302 (12/14) or 400 (16/18). The plan expected an empty list; it did not foresee that a re-block changes the terminating rule name, nor backend status codes.
- Note: Host-override cases (kbi-host-localhost, kbi-host-loopback-v4, first-wins) reach site demo (localhost aliases), not shopNN.
- G-U22: TestT4_, TestT5_ PASS; `make test-odoo` PASSED 48/48 on shop12, shop14, shop16, shop18.

## 2.3 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW tests/legit/{package.json,package-lock.json,.gitignore,playwright.config.ts,helpers.ts,run.sh,README.md}, specs/{backend,rpc,website}.spec.ts, deploy/compose/lab-tools.yml; Makefile `lab-legit`. node.bridge.yml: aliases shop{12,14,16,18}.lab.test on waf_lab.
- Deviations (non-weakening): (a) baseURL `http://shopNN.lab.test:8080` + network aliases, because `page.request` (Node HTTP stack) ignores Chromium `--host-resolver-rules` (flag kept for the browser); (b) backend views wait for the action-manager content, not `networkidle` (long-polling/bus never idles); (c) Odoo 18 ignores `/web#` URLs → `/odoo/crm`; (d) login form scoped to `form.oe_login_form` and URL wait excludes `/web/login`; (e) contact form selector also matches `/website_form/` (12/14). (f) a test timeout of 120 s.
- Run 575814f8: 12/12 passed, wafGuard empty; T-LEG1: 448 events tagged `575814f8-legit`, 0 BLOCK. Counted (not blocking): SizeRestrictions_BODY on call_kw create/write/attachment, CrossSiteScripting_BODY on message_post — exactly the expected odoo-common families. Contact form submitted on all 4 versions (200 ALLOW).
- G-U23 PASS.

## 2.4 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- NEW lab/nikto/Dockerfile, scripts/{lab-attack,lab-matrix}.sh, scripts/sql/{matrix,legit}.sql; lab-tools.yml services nuclei, nikto (+ volume nuclei-templates); Makefile lab-attack, lab-matrix.
- Deviations (non-weakening): (a) nikto tag 2.6.1 cloneable, but it needs `perl-xml-writer` → added to apk list; (b) SQL schema strings copied from snippets/clickhouse-ddl.sql column lists (CODEC removed; quotes escaped); `date_time_input_format='best_effort'`; (c) raw logs keep the client's header-name case → SQL derives `waf_test` from request_headers case-insensitively; (d) section 1 splits disagreements by the real user_class values (backend/website/static/realtime/other), not human/bot; (e) nikto runs are recognised by the UA (`<RUN_ID>-nikto`), nuclei by X-Waf-Test; (f) COMPOSE_IGNORE_ORPHANS in lab-attack.sh.
- Run 85c5a23c (11 min 40 s): nuclei 0 findings on all 4 sites (outputs empty); nikto 100 % blocked by UserAgent_BadBots_HEADER (4914 req/site). Matrix 26-11-2026: 5 sections; legit.sql → 0.
- Finding (open, for hardening later; not a gate): nginx-native errors before site assignment (e.g. TRACE → 405, malformed → 400) answer with `Server: nginx`; nikto reports "Server banner changed from 'awselb/2.0' to 'nginx'". Recorded as a fidelity gap vs ALB.
- G-U24 PASS.

## 2.5 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- Tuning loop: iteration 1 converged (no profile change). make lab-legit (RUN_ID d496b68a) 12/12, 0 BLOCK; make test-odoo 48/48 ×4; make test-e2e PASSED 62/62; TestPRF1_ PASS.
- Evidence (legit-only matches): SizeRestrictions_BODY COUNT on /web/dataset/call_kw (18/18/18/15 per site), CrossSiteScripting_BODY COUNT on call_kw (6/6/6/5). GenericRFI_BODY never matched by legit flows: kept in odoo-common as preventive (documented in docs/odoo.md), no exception added. Version profiles stay empty extends.
- NEW docs/odoo.md, docs/lab-matrix-001.md (matrix 26-11-2026); README "Lab Odoo" section + doc links.
- G-U25 PASS.

## P2 attempt 1 — DONE (26-11-2026 UTC, agent-1:opus)
- G-P2 on the running lab: `make lab-up test-e2e test-odoo lab-legit lab-matrix` rc 0 (odoo12–18 ready; PASSED 62/62; test-odoo 48/48 ×4; legit RUN_ID d5b1637d 12/12; matrix written) and `scripts/lab-matrix.sh --sql legit.sql` → 0. lab-smoke.sh ALL PASS. `go vet` clean, 7 packages ok. G-U21..G-U25 PASS.
- Review (agent-1, self-review): D27 — odoo profiles use only rule_action_overrides→count + label custom rules (TestPRF1_ PASS, `wafctl validate` reports shop sites nginx-only only because of client_ip xff, which is lab topology, not profile). Exceptions: every reason checked; none turns a block into an allow on a non-Odoo path (5 are re-blocks with a different terminating rule, 2 are backend status codes, body-limit-8k is AWS-equivalent 8 KB inspection). Matrix: legit 0 BLOCK; nikto 100 % blocked (UserAgent_BadBots_HEADER); nuclei 0 findings, 20–25 % of its requests blocked (the rest are benign probes).
- README obligation met (Lab Odoo section, docs/odoo.md, docs/lab-matrix-001.md).
- Open finding carried forward: nginx-native errors (TRACE 405, malformed 400) show `Server: nginx` (2.4).

## 3.1 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW deploy/compose/{central,central.bridge}.yml, deploy/clickhouse/{initdb/001-schema.sql,initdb/002-users.sh,config.d/waf.xml}, deploy/vector/central.yaml, internal/render/{vector,vector_test}.go, internal/secrets/{secrets,secrets_test}.go, cmd/wafctl/{secrets,engine}.go, tests/e2e/central.sh. WRITE node.yaml (vector), node.yml, write.go (compact meta.json), apply.go (vector restart when forward.yaml changes), docker.go (role files, env WAF_{DATA,CONFIG,CENTRAL}_DIR + WAF_NODE_ID, --env-file secrets.env, Restart), Makefile (geoip-test, secrets init, central files), .gitignore (secrets.env), lab-init-odoo.sh (same compose files).
- Recovery boundary (§6): first ClickHouse init at 26-11-2026 23:56 UTC on .run/central/clickhouse (initdb ran 001 + 002; users waf_admin/waf_ingest/waf_ro).
- Deviations (non-weakening, all verified):
  - `central.bridge.yml` (new file): all-in-one bridge joins clickhouse + vector-central to waf_lab (plan text: "they also join waf_lab").
  - forward sink address `http://<host:port>`: Vector's `vector` sink defaults to TLS without a scheme ("wrong version number"); P5 switches to TLS.
  - Vector 0.62 does not interpolate `${VAR}` unless VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true (set on vector-central only; ingest password was sent literally → 516 AUTHENTICATION_FAILED).
  - Geo: Vector `geoip` table rejects GeoIP2-Country ("Unsupported MMDB database type… use mmdb") → `geo_country` uses `type: mmdb` (raw record, `country.iso_code`, already in the VRL). Chosen over the pre-authorized City fallback because it keeps the Country download. ASN stays `geoip`.
  - Node pipeline latency: Vector 0.62 file sources back off when idle (measured up to ~8 s) independently per source; access/audit halves could be read seconds apart and split the join (observed: audit-only event with ts 1970 + access-only event). Fix: one file source `waf_logs` for both files (shared read pass) + reduce `max_events: 2` (flush when both halves present), `flush_period_ms: 500`, expire 3000 unchanged. Snippet vector-node.yaml is superseded on this point.
  - Disk buffer of fwd_central adds up to ~10 s after idle (memory buffer: steady 3 s); disk buffer kept (durability, plan). central.sh therefore warms the pipeline before T-C1 (first-event idle latency printed, 4–13 s) and T-C2 waits up to 30 s; T-C1 still requires all corpus events within 10 s of the run.
- Observed header-key case in waf.events.request_headers: original case (`X-Waf-Test`).
- G-U31: TestC0_ForwardRender, TestC0_MetaSingleLine, TestSEC1_ PASS; central.sh ALL PASS 3/3 consecutive runs (T-C1 62/62 ≤ 10 s, matches 62, heartbeat, GB, SE + ASN 29518, agg ≥ 62). smoke/apply/joinlog still ALL PASS.

## 3.2 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW internal/ch/{ch,raw,schema,ch_test}.go + internal/ch/migrations/001-schema.sql (embedded copy of deploy/clickhouse/initdb/001-schema.sql; go:embed cannot reach outside the module — TestQ4_ asserts byte identity), internal/logs/{query,search,show,tail,logs_test}.go, tests/e2e/cli.sh (3.2 section; 3.3–3.5 append). cmd: `logs search|show|tail` (+ `--raw DIR`), usage text.
- Design notes: window = `fromUnixTimestamp64Milli({from_ms:Int64},'UTC')` (no server-timezone parsing); sites as `{site:Array(String)}` with escaped literal; `--rule` = exact or `/NAME` suffix of terminating_rule (covers `custom:site/Name`), `--matched` = subquery on waf.matches; `output_format_json_quote_64bit_integers=0`. Raw mode defines waf.events/waf.matches as views over `/raw/*/…jsonl` and waf.agg_* as views with the MV SELECTs from the DDL, so the identical SQL runs offline.
- G-U32: TestQ1_, TestQ2_, TestQ3_, TestQ4_ (+ TestQR1_ raw params) (47 events columns, counted from the DDL) PASS; cli.sh ALL PASS (search blocks demo 531 ≥ 44, rule filter, show → 2 matches, T-Q5 raw = CH 2866 = 2866).

## 3.3 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW internal/logs/{awsfmt,export,awsfmt_test}.go + testdata/aws-*.json (goldens, `-update`). cmd `logs export`. Raw mode now streams `clickhouse local` stdout (no full buffering). cli.sh 3.3 section.
- Mapping decisions (fixed in goldens): terminatingRuleId = rule part after the last `/` of terminating_rule (managed and `custom:<site>/<Name>`); DEFAULT terminating_type → `Default_Action` + type `REGULAR` (AWS uses REGULAR for the default action; DEFAULT is not an AWS value); custom → REGULAR. ruleGroupList/nonTerminating only consider matches AWS would evaluate (in_scope=1, post_terminating=0); groups in rule-id (= evaluation) order; custom COUNT matches go to top-level nonTerminatingMatchingRules. Headers sorted by name (Map loses order). `--limit` is not applied by export (whole window, streamed).
- G-U33: TestX1_ (3 goldens), TestX2_ (csv header) PASS; cli.sh ALL PASS (aws lines parse, aws count = search count 2729, NoUserAgent terminatingRule present, csv rows = 2729, jsonl --with-matches --gzip).

## 3.4 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW internal/stats/{sql,stats,stats_test}.go + testdata/rule-table.golden, cmd/wafctl/stats.go (`stats`, shared windowFlags for report). cli.sh 3.4 section.
- Notes: window params are `{from_ms:Int64}`/`{to_ms:Int64}` (instead of a single `{since:DateTime64(3)}`, so --from/--to work too); site filter exactly `(empty({site:Array(String)}) OR site_id IN {site:Array(String)})`. agg_requests_1m has no shadow_action → `shadow_block` is always a scalar subquery on events (also in agg mode). Agg windows are minute-aligned at the start. Agg SQL qualifies columns (`a.requests`) because aliases equal to column names trigger ILLEGAL_AGGREGATION in CH 26.8. Extra flag `--sort-blocks` (top-N views by blocks; used by the report's "top blocked paths"). TERMINATING = post_terminating=0 AND configured_action≠COUNT (in_scope not in agg; same definition both sources).
- G-U34: TestS1_, TestS2_, TestS3_ PASS; cli.sh ALL PASS (NoUserAgent_HEADER matches 30, overview block 472 ≥ 52, agg overview, --counted only COUNT rules).

## 3.5 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW internal/report/{report,svg,template.html,report_test}.go, internal/ch/migrate.go, cmd/wafctl/report.go (`report --html`, `ch migrate`, `ch retention`). cli.sh 3.5 section (cli.sh now covers 3.2–3.5). `deploy/systemd/`: none (as planned).
- Report: html/template + embedded CSS, inline SVG (horizontal bars, per-hour stacked ALLOW/BLOCK/FAIL columns); 9 sections with fixed ids; all data via the stats SQL (+ Timeline/Disagreements/Fails constants in stats/sql.go). Section 7 combines IPs and countries. Long cells truncated at 160 chars. Config snapshot = meta.json of runtime/current + per-site compat line (same logic as `validate`), only when $WAF_CONFIG_DIR/node.yaml exists. Visual check via Playwright screenshot.
- Migrations: `waf.schema_migrations` is ReplacingMergeTree(version) (plan gave only the columns); 001 adopted when waf.events exists. HTTP runs one statement per request → Statements() splits on `;\n` (8 statements in 001).
- Retention: `ALTER … MODIFY TTL … + INTERVAL {days:UInt32} DAY DELETE` (parameterised; CH stores `_CAST(n,'UInt32')`, display normalised to `N DAY`). Admin user via WAF_CH_ADMIN_PASSWORD (env or secrets.env).
- G-U35: TestH1_, TestH2_, TestM1_ PASS; cli.sh ALL PASS 20/20 (report 24.8 KB, no external refs, NoUserAgent_HEADER; migrate idempotent; retention 20 → shown, restored 30; agg < raw rejected).

## 3.6 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW docs/observability.md (IT): flusso dati, stack centrale + utenti, tabelle + significato campi, comandi logs/stats/report, `--raw`, export + mappatura AWS, retention, migrazioni, GeoIP. WRITE README.md (sezione "Osservabilità", mappa directory, link), docs/operations.md (`$WAF_CENTRAL_DIR`, ruoli/compose, `secrets init`, migrate/retention).
- G-U36 self-review evidence: every command in observability.md and the README section executed on the lab (logs search ×4 incl. --matched/--from/--ip, show, tail (timeout 5), stats ×5, report ×2, --raw ×2, export jsonl/csv/aws|jq, ch retention ×3, ch migrate, make geoip-test): all rc=0 (tail 124 by timeout). Claim "vector-central non parte senza i file GeoIP" verified (Vector: `Enrichment Table "geo_country": i/o error: No such file or directory`).

## P3 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- G-P3: `make test-unit` (0 FAIL) && `make lab-up` rc 0 && `make test-e2e` PASSED 62/62 && `tests/e2e/central.sh` ALL PASS (T-C1 62/62 ≤ 10 s, matches 62, heartbeat, GB/SE/ASN 29518, agg 136) && `tests/e2e/cli.sh` ALL PASS 20/20. G-U31..G-U36 PASS.
- Review (agent-1, self-review):
  - I-6: in the last hour `count()` 3863 vs `uniqExact(request_id)` 3856 → 7 duplicate rows, all at 00:08–00:09 UTC and also duplicated in raw/events.jsonl: one-off re-read when 3.1 replaced the two file sources (`waf_access`/`waf_audit`) by `waf_logs` (new source id = no checkpoint). No duplicates in any 5-minute window after 00:10 across rotations and restarts. Steady state holds I-6; noted in Do-not-repeat (renaming the node file source re-reads the current logs).
  - I-7: DDL `DateTime64(3,'UTC')`; window params are epoch ms (`fromUnixTimestamp64Milli(…,'UTC')`); `--from` without zone rejected (TestQ2_); CLI/report print UTC with `Z`/"UTC".
  - SQL parameterisation: all user values are `{name:Type}` params (TestQ1_ asserts absence of values from SQL); string concatenation in ch/logs/stats only joins constants (fixed fragments, DDL column names, fixed table lists). `ch retention` days are a `{days:UInt32}` param. No injection path found.
  - Docs: observability.md copy-paste checked (3.6).
- README obligation met (Osservabilità section, docs/observability.md, operations.md).

## 4.1 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW internal/central/{config,render,central_test}.go + templates/prometheus.yml.tmpl + testdata/prometheus.yml, tests/e2e/metrics.sh, cmd `central render`. WRITE render/vector.go (metrics in forward.yaml), nginx.conf.tmpl (status listen), deploy/vector/central.yaml (vrl route conditions, `metric` route, `prom` exporter :9598), compose node.yml (/proc,/sys ro + PROCFS_ROOT/SYSFS_ROOT), central.yml (prometheus), cmd apply/validate (central.yaml), apply.go (rollback), Makefile (prometheus/data).
- Deviations (non-weakening):
  - Template embedded from `wafctl/internal/central/templates/` instead of `deploy/prometheus/prometheus.yml.tmpl` (go:embed cannot leave the module).
  - Metric sources + `m_tag` are rendered into `forward.yaml` with literal values (status URL by network, node_id) instead of `${WAF_NGINX_STATUS_URL}`/`${WAF_NODE_ID}` in node.yaml: Vector 0.62 would need VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION on every node. Same sources/collectors/interval as the plan.
  - central.yaml validation lives in cmd validate/apply (`central.Config.Validate`) rather than config/validate.go (avoids a config↔central dependency); same checks, apply refuses on errors.
  - prometheus runs as `user: "0:0"` (bind-mounted data dir created by wafctl/docker is not owned by the image's nobody user). Not published.
  - Role `central`: apply renders central files and runs compose up (no nginx). all-in-one: central render before the node apply, then compose up -d (starts new services) and restarts services whose rendered dir hash changed.
- Found + fixed: changing the status `listen` (127.0.0.1:8090 → 8090) cannot be applied by reload (`bind() to 0.0.0.0:8090 failed (98: Address in use)`): apply timed out with `current` already pointing at the new rev. apply now restores `current` to the previous rev on that timeout and says a container restart is needed (TestA3_). Lab transitioned with `docker restart waf-waf-1` + apply.
- Actual metric names (for 4.2): `nginx_http_requests_total` (plan: nginx_requests_total), `vector_buffer_size_bytes` (plan: vector_buffer_byte_size), `nginx_connections_active`, `host_cpu_seconds_total`, `host_memory_available_bytes`, `ClickHouseMetrics_Query` as planned; `vector_component_errors_total` appears only once an error happened.
- G-U41: TestCEN1_, TestCEN2_ PASS (+ TestCEN0_ render, TestA3_); metrics.sh ALL PASS (up 3 targets, nginx_connections_active{node_id="lab-node-1"} 1 series, host metrics); central.sh, apply.sh, joinlog.sh ALL PASS; test-e2e 62/62. host_metrics filesystem collector works (no permission error).

## 4.2 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW deploy/grafana/panels.py (4 dashboards, 28 panels), scripts/gen-dashboards.py (stdlib; `--check` = unique titles, grid in 24 cols without overlap, committed JSON current), deploy/grafana/dashboards/*.json (generated), scripts/check-dashboards.sh, internal/central/grafana.go (provisioning files + GrafanaAPI AddUser/Users, RandomPassword), cmd/wafctl/grafana.go (`grafana user add|list`), tests/e2e/grafana.sh (10 checks). WRITE render.go (grafana component), central.yml (grafana service), secrets.go (GF_ADMIN_PASSWORD key), docker.go/engine.go (GF_BIND/GF_ROOT_URL from central.yaml into compose env), Makefile (`dashboards`, grafana/data dir).
- Deviations (non-weakening):
  - `allValue` is `"'__all__'"` (quoted), not `"__all__"`: Grafana inserts a custom allValue verbatim and ignores `:singlequote`, so the plan value produced `site_id IN (__all__)` → ClickHouse UNKNOWN_IDENTIFIER on every panel (seen in Grafana logs/UI). check-dashboards.sh now interpolates like Grafana (allValue verbatim, textbox sqlstring → '') instead of hard-coding '__all__', so it would have caught it.
  - Prometheus metric names per 4.1 record: `nginx_http_requests_total`, `vector_buffer_size_bytes`.
  - Grafana runs as user 0:0 (bind-mounted data dir), like prometheus.
  - Panel dict also accepts `stack`, `legend`, `x` (barchart x field); stats use colorMode none.
  - Provisioning file `grafana/provisioning/alerting/` not yet rendered (4.3); Grafana logs a harmless "can't read alerting provisioning" until then.
- Visual check (Playwright screenshots, logged in as admin): overview/tuning/explorer/nodes render with data, no panel errors.
- G-U42: TestG1_ PASS; gen-dashboards.py --check OK; check-dashboards.sh ALL PASS (31 queries incl. variables; a broken SQL is reported FAIL with the CH error); grafana.sh ALL PASS (4 dashboards in folder WAF, ch/prom health OK, anonymous 401, viewer read-only 403 on write, dup user rejected); apply idempotent (grafana not restarted when unchanged); metrics.sh, apply.sh ALL PASS.

## 4.3 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW internal/central/alerts.go (5 rules from thresholds, contact point, policies, apprise yml), deploy/compose/lab/alert_sink.py, tests/e2e/alerts.sh, lab/config/central.yaml (block_spike_per_5m 20), lab/config/apprise-urls.txt (json://alert-sink:8000/, committed: no secret). WRITE render.go (apprise component; change detection on rendered files only), central.yml (apprise 2.2.0, alert-sink profile test), Makefile + scripts/lab-env.sh (`COMPOSE_PROFILES=test` for the lab; apprise dir).
- Deviations / findings (non-weakening):
  - R6 residual: Grafana **file** provisioning expands `$NAME` in contact-point settings, so the verified template's `$t` arrived empty (`template: :1: unexpected ":=" in command`). Rendered as `$$t`; the stored template is the verified one (checked via the receivers API). Rule annotations (`$labels`, `$values`) are not expanded.
  - apprise/waf.yml tags every URL `waf` (`- "url":\n    - tag: waf`), not a bare list: the contact point notifies `tag: waf` and apprise only notifies URLs carrying the requested tag (apprise-api README). URLs are JSON-quoted.
  - T-AL5 load: `oha -H 'User-Agent:'` still sends oha's User-Agent (requests were ALLOWed). The spike uses an XSS query argument (CrossSiteScripting_QUERYARGUMENTS, 403) with oha; same 300 blocked requests on demo.
  - Change detection hashes only the files wafctl renders (filesHash): apprise writes `.scheduler.pid`/`store/` into /config, which restarted apprise on every apply with a dir hash. Test extended (state files ignored; a threshold change restarts only grafana).
  - Receiver test API needs body `{"integration": <spec.integrations[0]>}`; receiver name is the base64 uid (`YXBwcmlzZQ`), looked up by title in alerts.sh.
  - In the lab `waf-ingest-lag` fires for idle sites (by design: "no traffic or ingest stalled"); documented in 4.4.
- Observed once: `tests/e2e/cli.sh` FAILED 2 checks right after the regression loop (output not kept); not reproduced in 8 reruns (incl. the same sequence). Suspect ingest timing (raw vs ClickHouse counts). Watch in G-P4.
- G-U43: TestAL1_ (rules golden, fail threshold gt 0), TestAL2_ (apprise skips comments, empty → `urls: []`) PASS; alerts.sh ALL PASS (T-AL3 5 rules ok; T-AL4 `[WAF] TestAlert` at the sink; T-AL5 `[WAF] WAF block spike` "site demo: 306 blocked requests in 5 min (threshold 20)" after 205 s). grafana, metrics, central, apply ALL PASS; test-e2e 62/62.

## 4.4 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW docs/dashboards-alerts.md (Italian): data flow, access (SSH tunnel, Tailscale via grafana.bind/root_url, no 0.0.0.0), admin password, `wafctl grafana user`, every dashboard/panel with its tuning meaning, editing dashboards (panels.py → make dashboards → check-dashboards.sh), alert table with central.yaml thresholds and grouping, ingest-lag caveat, apprise URLs for Slack/Google Chat/Telegram with wiki links + .gitignore note, lab (alert-sink, e2e scripts). WRITE README.md ("Dashboard e alert" section, dir map, docs list), docs/operations.md (GF_ADMIN_PASSWORD, central.yaml render/restart, listen-change restart), tests/README.md (e2e scripts table).
- Fix found while checking commands: tests/e2e/grafana.sh `g()` dropped extra curl args, so the e2e user cleanup (DELETE) never ran; fixed, leftover users deleted, grafana.sh ALL PASS.
- Copy-paste checked on the lab: `wafctl central render`, `wafctl grafana user add|list`, `grep GF_ADMIN_PASSWORD …`, `docker logs waf-alert-sink-1 | grep ALERT-SINK`, the three e2e scripts. G-U44: self-review done.

## P4 attempt 1 — PHASE 4 DONE (27-11-2026 UTC, agent-1:opus)
- G-U41..G-U44 passed (units 4.1–4.4).
- G-P4: `make lab-up` rc=0 (full lab incl. Prometheus, Grafana, apprise, alert-sink); `scripts/check-dashboards.sh` ALL PASS; `tests/e2e/alerts.sh` ALL PASS. Also cli.sh, metrics.sh, grafana.sh ALL PASS after lab-up (the 4.3 cli.sh flake did not recur).
- Gate strengthened during G-P4: T-AL5 matched any `[WAF] WAF block spike` line, and the first run after lab-up passed on a *resolved* notification for site tuned. Now it waits until no demo alert is firing, then requires `firing: N alert(s). site demo:` (passed: "site demo: 301 blocked requests in 5 min (threshold 20)" after 210 s).
- Review (agent-1):
  - secrets: none of the 4 secret values appears in tracked files or in rendered central files (datasource uses the literal `$WAF_CH_RO_PASSWORD`); secrets.env / *.pem not tracked;
  - Grafana anonymous access off (401 on API without auth), sign-up off, published only on 127.0.0.1:3000; Prometheus and apprise not published;
  - alerts deliver end to end (contact-point test and real spike) through apprise to the sink.
- Residual: waf-ingest-lag fires for idle sites (documented; threshold per central.yaml).

## 5.1 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW wafctl/internal/pki/{index,ca,issue,crl,token,pki_test}.go, cmd/wafctl/pki.go (`pki init|issue|revoke|list|crl|token`), tests/e2e/pki.sh (15 openssl-backed checks). WRITE main.go, env.go (`PKIDir`: $WAF_PKI_DIR, default $WAF_CONFIG_DIR/pki), .gitignore (`/lab/config/pki/`).
- Contract as planned: ECDSA P-256; CA 10 y (IsCA, MaxPathLenZero, CertSign|CRLSign); leaves 90 d from now−5 min, DigitalSignature, client EKU ClientAuth + SAN DNS=cn, server EKU ServerAuth + SANs from flags; 128-bit random serials; CRL v2 via x509.CreateRevocationList, next_update +7 d, number +1 per generation; flock on index.json.lock for every write; private/ 0700, ca.key 0600 PKCS#8; tokens 32 random bytes base64url, only sha256 stored (tokens.json 0600), constant-time compare, single use, bound to cn, injected clock.
- Shape decisions (non-weakening): index.json is `{"crl_number": n, "certs": [...]}` (the plan lists both an entry array and an index-level crl_number); `revoke <cn>` revokes every non-revoked cert of that CN; `SignCSR` (CSR signature, CN match, P-256 only) is added now for 5.3; `pkiAfterCRL` hook left for 5.2 (copy CRL to ingress + reload); CN restricted to `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; token ttl ≤ 720h; leaf NotAfter capped at the CA's.
- Self-review (security): crypto/rand only; file modes checked by tests and pki.sh; client cert rejected for ServerAuth (Go + openssl -purpose); CA key never printed or copied.
- G-U51: TestPKI1_..TestPKI5_ PASS (5); openssl verify OK, CRL lists the revoked serial and `openssl verify -crl_check` → "certificate revoked" (pki.sh ALL PASS).

## 5.2 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW wafctl/internal/central/ingress.go:
  - `Ingress{bind, ingest_port, pki_port, server_names, server_ips}` in central.yaml; default 0.0.0.0:6000/6001; validated.
  - `IngressConf`: the R10 probe shape, i.e. stream, `ssl_alpn h2`, `ssl_verify_client on`, `ssl_crl`, `verify_depth 1`, proxy to vector-central:6000.
  - `RenderIngress` writes `$WAF_CENTRAL_DIR/ingress/{nginx.conf,certs/{ingress.pem,ingress.key 0600,ca.pem,crl.pem}}` and never copies the CA key. The server cert (CN ingress, SANs = server_names+ingress, server_ips) is reissued if missing, expiring in < 30 d, from another CA, or if the SANs changed.
  - `PublishCRL`.
- NEW compose files:
  - service `ingress` in central.yml, published on `${INGRESS_BIND}:${INGRESS_PORT}`;
  - central.host.yml, which moves vector-central for the local all-in-one node to 127.0.0.1:6100 (6000 is now the ingress, and vector-central is no longer published);
  - node.bridge-ext.yml, a separate network for a second compose project on the same host;
  - lab-node2.yml, which adds `extra_hosts central.lab.test:host-gateway` so node 2 goes through the host like a remote node.
- NEW deploy/systemd/wafctl-pki-crl.{service,timer} (daily, R10). NEW lab/config-node2/{node.yaml,sites/demo.yaml}. NEW tests/e2e/multinode.sh (part1).
- WRITE:
  - render/vector.go: role node → `tls {enabled, crt_file, key_file, ca_file: /etc/waf/certs/_node/*, verify_hostname: true}`; all-in-one stays plain on the local network.
  - node.yml: vector mounts `$WAF_DATA_DIR/certs/_node`, which apply creates with mode 0700.
  - node.bridge.yml: ports follow node.yaml listen via WAF_HTTP(S)_PORT.
  - engine.go: exports those ports plus INGRESS_BIND/PORT.
  - cmd apply.go: renderCentral needs the PKI (clear error otherwise) and adds "ingress" to the changed services.
  - pki.go: `pkiAfterCRL` publishes the CRL and runs `nginx -s reload` in the ingress.
  - Makefile: lab-up creates the lab CA.
  - lab central.yaml: ingress server_names [ingress, central.lab.test].
  - .gitignore: lab pki dirs.
  - docs/observability.md, tests/README.md.
- Decision (non-weakening): all-in-one keeps the local hop in plaintext, either on the compose network or on loopback, because both ends run on the same host. Every remote hop uses mTLS.
- Stream access log lines are written at session end, and Vector's session is long-lived. So the ingress is verified with openssl handshake probes: no cert → `"-" NONE 500`, node cert → `CN=lab-node-2 SUCCESS 200`.
- G-U52: TestING1_ + TestFWD1_ PASS (2). multinode.sh part1 ALL PASS: T-MN1 delivered 20/20 node-2 events to ClickHouse through the ingress. Regression: central/smoke/apply/metrics ALL PASS. `wafctl pki crl` → CRL published and the ingress reloaded.

## 5.3 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW pki/serve.go: `Server` (GET /ca, POST /enroll, POST /renew, GET /healthz).
  - Per-IP token bucket: 10/min, 429 when exhausted.
  - Request bodies: max 64 KB, unknown fields rejected.
  - Auth failures return a generic message; malformed input returns 400.
  - /enroll validates the CSR (PEM, signature, P-256, CN regex) before `UseToken(token, csr CN)`, so a malformed or mismatching CSR does not burn the token. A CN mismatch or a bad, used or expired token → 403.
  - /renew requires a verified client cert with the ClientAuth EKU (none → 401). The index entry must be known, match the CN, be unrevoked and unexpired (otherwise 403). The CSR CN must equal the cert CN. The old serial gets `renewed_by`; it is not revoked.
  - `TLSConfig` uses the ingress server cert with `VerifyClientCertIfGiven` against the CA.
- NEW pki serve_test.go and issue.go `NewCSR`. index.go gains `Lookup` and `MarkRenewed`; Status gains `renewed`.
- NEW node/{enroll,renew,node_test}.go:
  - enroll fetches /ca with InsecureSkipVerify and pins the DER sha256 (mismatch → abort before anything is written). It then verifies the server against the pinned CA and checks that the returned cert matches the CA, CN and key. Files are written as `.new` + rename, with node.key 0600.
  - renew skips when > 30 d remain unless `--force`, then calls /renew over mTLS with the current cert.
  - Requests time out after 15 s.
- NEW cmd/wafctl/node.go: `node enroll|renew`. The default central is central.address:pki_port; vector is restarted if running.
- WRITE cmd pki.go: `pki serve [--addr :6001] [--rate 10]`, using the ingress cert and logging in UTC.
- NEW systemd units: wafctl-pki.service (Restart=always, outside Docker, I-8) and wafctl-node-renew.{service,timer} (daily, RandomizedDelaySec=1h).
- Lab central.yaml: ingress server_ips [127.0.0.1].
- Plan correction (non-weakening): the ingress gains `worker_shutdown_timeout 10s`. After the CRL reload, old workers would otherwise keep a revoked node's long-lived Vector session for up to proxy_timeout (10 m). With the timeout, the session drops within 10 s and the reconnect is checked against the new CRL. Without this, T-MN5 could not hold.
- G-U53: TestSRV1_–TestSRV4_ + TestND1_ PASS (5).
- multinode.sh (full) ALL PASS in about 70 s:
  - T-MN2: enroll with the token, wrong pin aborted, node.key 0600, events delivered.
  - T-MN3: token reuse → HTTP 403.
  - T-MN4: renew skips while the cert is fresh; `--force` issues a new serial, the old one shows `renewed`, and traffic flows.
  - T-MN5: revoke reloads the ingress; after 20 s there are 0 events, and the ingress logs "certificate revoked".
  - Cleanup: re-enroll delivers the 20 buffered events (disk buffer, no loss).

## 5.4 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW node/bootstrap.go and templates/{gitignore,node.yaml.tmpl,central.yaml.tmpl,default-wafctl,sites-README.md} (embedded).
  - `Bootstrap` validates node-id, role, network and central. It refuses if node.yaml exists unless `--force`.
  - It writes .gitignore (plan lines plus `secrets.env.tmp`), node.yaml, sites/README.md and profiles/.gitkeep. Central roles also get central.yaml (ingress.server_names = `--central`) and a 0600 apprise-urls.txt stub, which is git-ignored.
  - It runs `secrets.Init` (0600) and creates the `$WAF_DATA_DIR` subdirs (certs/_node 0700).
  - `--install-systemd` requires root. It copies deploy/systemd/*, writes /etc/default/wafctl, runs daemon-reload and `enable --now` on the role's units: node = bypass-expire, logs, node-renew; central = pki-crl, pki; all-in-one = everything except node-renew.
  - It ends with `git init` and a single commit `bootstrap <id>` using a repo-local identity, then prints the next steps.
- NEW cmd `node bootstrap`. NEW node/bootstrap_test.go (T-BS1/2), scripts/{build-release.sh,install-node.sh}, tests/e2e/bootstrap.sh. Makefile gains `release VERSION=`.
- WRITE env.Home: falls back to the directory of the (symlink-resolved) wafctl executable, so a release installed in /opt/nginx-aws-waf works without exporting WAF_HOME.
- build-release.sh:
  - builds linux/amd64 with CGO off, `-trimpath` and version ldflags;
  - ships docs/ without plans/, plus README;
  - refuses to package `*.key`, `*.pem`, `secrets.env*` or `tokens.json`.
- install-node.sh:
  - root only; requires docker compose (otherwise prints the Docker URL and exits 1) and git;
  - copies to `$WAF_HOME` and links /usr/local/bin/wafctl.
- In the e2e, a `docker compose version` shim stands in for Docker in the container (no Docker-in-Docker). The no-Docker refusal path is tested first.
- Not e2e-tested: `--install-systemd` (the container has no systemd). The root check and the unit lists are covered by code review only.
- G-U54: TestBS1_/TestBS2_ PASS (2). bootstrap.sh ALL PASS (10 checks: validate rc 0, 1 commit, secrets 0600 and untracked, second run refused).

## 5.5 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW deploy/terraform/{versions.tf,variables.tf,main.tf,outputs.tf,user-data.sh.tftpl,README.md,.terraform.lock.hcl}:
  - provider hashicorp/aws ~> 6.0;
  - `var.nodes` map name → {role, instance_type, subnet_id}, with validations for role and node_id;
  - SG `web`: 80/443 from 0.0.0.0/0 and ::/0, for node and all-in-one;
  - SG `central`: 6000/6001 only from `var.node_cidrs` (v4/v6), for central and all-in-one;
  - Ubuntu 24.04 AMI lookup (Canonical) or `var.ami_id`; IMDSv2 required; encrypted gp3 root;
  - user_data installs docker.io + docker-compose-v2 + git, downloads `var.release_url`, then runs install-node.sh and `node bootstrap --install-systemd`. Enrollment stays manual (one-time token).
  - Never applied (D30).
- Makefile:
  - `TF_IMAGE := hashicorp/terraform:1.17.2` (the plan's `hashicorp/terraform:1` tag does not exist; R4 addendum written);
  - `tf-validate` runs init -backend=false, validate and `fmt -check`, as the invoking uid so the files are not root-owned.
- .gitignore: `.terraform/`, tfstate, tfvars.
- NEW docs/multi-node.md (Italian): topology (on-prem / AWS / tailnet), ports and firewall, PKI layout and modes, init, token/enroll (pinning), renew, revoke (10 s session drop), the expired-CRL warning with check commands, CA backup (offline, encrypted), install (release → install-node → bootstrap), Tailscale, Terraform, the two-node lab.
- WRITE README.md: Multi-nodo section, directory map, doc index. WRITE docs/operations.md: systemd table with node-renew, pki-crl and pki.
- G-U55: `make tf-validate` → "Success! The configuration is valid."; fmt -check clean.

## P5 attempt 1 — PHASE 5 DONE (27-11-2026 UTC, agent-1:opus)
- G-P5:
  - `make test-unit`: 14 packages ok, 0 FAIL.
  - `make lab-up`: rc 0.
  - `tests/e2e/multinode.sh`: ALL PASS (21 checks).
  - `tests/e2e/bootstrap.sh`: ALL PASS.
  - `make tf-validate`: Success!
- G-SEC: `git ls-files` and `git log --all --name-only` show no .pem, .key, secrets.env, tokens.json or apprise-urls.txt, apart from the allowed lab apprise file.
- Regression: smoke, apply, central, metrics, cli, grafana, pki and alerts ALL PASS; check-dashboards ALL PASS.
- Phase fix: the second lab node now writes lab-node-2 events into the shared ClickHouse. cli.sh T-Q5 and X-* compared ClickHouse (all nodes) against node 1's raw dir. Fix: new `--node ID` filter on logs search/export/stats (`node_id = {node:String}` parameter; TestQ1 extended with an injection value and the placeholder). cli.sh now scopes those checks to `--node lab-node-1`. docs/observability.md updated.
- Review (self-review, security):
  - I-8: no compose service mounts `$WAF_CONFIG_DIR` or the PKI. The ingress mounts only `central/ingress/certs` (ingress.pem/key, ca.pem, crl.pem). `pki serve` runs on the host (systemd).
  - Modes: private/ 700; ca.key, tokens.json, ingress.key, node.key and secrets.env 600; certs/_node 700.
  - Tokens: sha256 only, constant-time compare, single use, bound to a CN, and never burned by an invalid or mismatching CSR.
  - Revocation: verified end to end (0 events after the revoke, ingress logs "certificate revoked"); the CRL timer is in place and documented.
  - Docs: multi-node.md warns about an expired CRL and covers the CA backup.

## 6.1 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- The rate limit and geo block features already existed (P1). This unit proves them end to end.
- NEW lab/config/sites/{ratelimit,ratecount,geo}.yaml: generic echo sites with xff, profile aws-default. WAF keys sit inline in the site file, as the Site struct inlines WAF; the plan's sketch had no `waf:` wrapper.
- NEW tests/corpus/optional.yaml:
  - geo-gb → 403 GeoBlock;
  - geo-se → 200 Default_Action;
  - geo-v6-jp → 200 Default_Action (the runner requires terminating_rule).
- NEW tests/e2e/ratelimit.sh. Each run uses a distinct 198.51.100.x client, because limit_req state survives the 60 s window.
  - ratelimit: 40 requests → 11×200 (burst 10 + 1) and 29×403. Access log `rl=REJECTED` = 29. ClickHouse has 29 events with `terminating_type=RATE_BASED`, `action=BLOCK` and `rate_limit_status=REJECTED`.
  - ratecount: 40×200, `REJECTED_DRY_RUN` on 29 requests, 0 BLOCK events.
- WRITE lab/config/node.yaml: `geoip.enabled: true` (MaxMind test DBs). lab-min-up already runs geoip-test when the mmdb is missing, which is equivalent to the dependency the plan asks for.
- NEW TestR13_ (SecGeoLookupDb, plus the GeoBlock custom rule `@rx ^(?:GB)$` before the first managed group) and TestR14_ (`rate=10r/m`, `burst=10`, no dry_run for block).
- G-U61: 2 PASS. `make test-e2e` PASSED 65/65 (with optional.yaml). ratelimit.sh ALL PASS. Regression: smoke, apply, central and cli ALL PASS; go test 0 FAIL.

## 6.2 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW wafctl/internal/awsexport:
  - model.go: Build with the order rate → start customs (GeoBlock first) → group + after: customs, and priorities 0, 10, 20, …. Overrides are emitted only when they differ from the catalog default. A count-mode site makes everything Count. Also holds LossyError and the manual_steps.
  - stmt.go: the condition → statement table, IP sets split into v4/v6 with placeholder ARNs, and bare IPs turned into /32 or /128.
  - json.go.
  - hcl.go: a stub for 6.3.
- Golden files and fixtures live under testdata/{golden,config}.
- NEW cmd/wafctl/exportaws.go: `export-aws` command. Lossy reasons → exit 2 with the list. Config is validated before export.
- NEW scripts/aws-validate-acl.sh (create-web-acl or --ip-set): uses the local aws CLI 2.35.21, falling back to the docker image `amazon/aws-cli:2.35.21`, pinned to the same version (§6 pin). The fallback was tested with a PATH that has no aws: VALID.
- Makefile: `aws-export-check` runs the T-EXP7 loop.
- G-U62: TestEXP1–6 6 PASS. T-EXP7: all 12 lab sites VALID. The golden web_acls and the IP set are VALID too. A negative control without a complete VisibilityConfig → INVALID rc=252. The shop18 lossy list is `["client_ip.source=xff"]`. make test-unit: 15 ok.

## 6.3 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW wafctl/internal/awsexport/hcl.go: a generic walker over web_acl. Attributes are sorted (name and priority first) and aligned the way terraform fmt aligns them; blocks follow, sorted.
  - The IP set ARN becomes the expression `aws_wafv2_ip_set.<tf>.arn`.
  - `${` is escaped to `$${` and `%{` to `%%{`.
  - Also emits the terraform/provider/variable alb_arn/association blocks, plus comment lines for manual_steps (without the JSON-only IP set step) and lossy.
- **Plan correction, mapping table (non-weakening):** `CloudWatchMetricsEnabled` → `cloudwatch_metrics_enabled` was added to the snake special cases. The plain split gives `cloud_watch_…`, which the provider does not know.
- NEW hcl_test.go: TestTF1 (golden tunedaws.tf), TestTF2 (escaping) and TestTF3 (unquoted ARN expression).
- NEW scripts/tf-validate-export.sh: runs init -backend=false, validate and fmt -check in a temp dir, on the TF_IMAGE pinned in the Makefile. Plugin cache in build/.tf-plugin-cache.
- WRITE lab/config/sites/allowlist.yaml: custom rule OfficeAllow (start, allow, ip_set [203.0.113.200/32, 2001:db8::1/128]), as the plan's fixture asks.
  - **BUG found and fixed (render):** libmodsecurity 3 rejects an IPv6 `/128` inside `@ipMatch` ("Rules error", nginx -t fails). `render/conds.go` `ipMatchList` now writes full-length prefixes as bare addresses.
  - NEW TestR15_. New corpus cases allowlist-ipset-v4 and allowlist-ipset-v6 (OfficeAllow wins over IpReputation: first-wins).
- G-U63: TestTF1–3 3 PASS. `tf-validate-export.sh build/aws/shop18.tf` → VALID; tuned.tf and allowlist.tf (IP sets v4+v6) → VALID. The rated, tunedaws, shadowed and methods fixtures → VALID.
- Regression: corpus PASSED 67/67, make test-unit 0 FAIL, aws-export-check all VALID.

## 6.4 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- WRITE scripts/fetch-ip-lists.sh: `OUT="${OUT:-$ROOT/data/ip-reputation}"` (a one-line diff).
- NEW wafctl/internal/lists/update.go, `Update`. Order of work:
  1. Fetch into a tmpdir.
  2. Validate every line of every list with netip; an error names `file:line` and nothing is installed.
  3. Apply the 50 % guard (`kept` unless --force). Content is compared on entries only, so the timestamp header is ignored.
  4. Install through tmp + rename.
  5. Print the `LIST OLD NEW STATUS` table.
  - The managed lists are the 4 the script produces.
  - **Plan addition (non-weakening):** `custom-reputation.txt` and `HostingProviderIPList.txt` are created comment-only when missing (`created`) and never touched afterwards. The catalog references both through @ipMatchFromFile, so without them nginx -t fails on a new node.
- NEW cmd/wafctl/lists.go: `wafctl lists update [--force] [--no-apply] [--script]`. It runs apply only when something changed.
- NEW deploy/systemd/wafctl-lists.{service,timer} (04:17 UTC, RandomizedDelaySec=30m) and wafctl-geoip.{service,timer} (weekly; geoipupdate v8.0.0 tag verified on Docker Hub; then apply). systemd-analyze verify is clean.
  - The bootstrap Timers for node and all-in-one now include wafctl-lists.timer. The geoip timer is enabled by hand because it needs a MaxMind account.
  - The bootstrap next-steps text now says `wafctl lists update`.
- Docs: operations.md has the "Liste IP" and "GeoIP" sections plus the systemd table; multi-node.md updated.
- G-U64: TestLST1–3 3 PASS.
  - Online `wafctl lists update` on the lab: table with 3 lists updated, DDoS unchanged, apply ran. The corpus `iprep-*`/`anonip-*` cases pass (67/67).
  - Offline (`unshare -rn`): 3× kept, rc 0, files untouched, no apply.
  - A second online run: everything unchanged, apply skipped.
  - Regression: bootstrap.sh ALL PASS, make test-unit 0 FAIL.

## 6.5 attempt 1 — DONE (27-11-2026 UTC, agent-1:opus)
- NEW scripts/final-check.sh with Makefile target `final-check`. It runs the 8 G-FINAL steps in order, stops at the first failure and prints `G-FINAL step N OK (details)`. Logs go to build/final-check/.
  - Step 3 measures the delay to ClickHouse right after the corpus. It counts events with `request_headers['X-Waf-Test']` starting with the run id, so step 2 (Playwright) does not mask the delay.
  - Step 6 checks the attack under bypass (≠403, event shadow_action=BLOCK) and a 403 after `bypass clear`. A trap clears the bypass if the script fails.
  - Step 7 runs `alerts.sh --spike-only`.
  - Step 8 checks the lossy list from the HCL comments.
- **BUG found and fixed (Vector, node):** the first final-check run measured about 12 s to ClickHouse, above the 10 s G-FINAL limit.
  - Measurement: a corpus burst reached raw/ on the node only after about 7 s, all at once. The cause is the file source's default `max_read_bytes` of 2048 B per file per pass, against audit lines that carry bodies.
  - `deploy/vector/node.yaml` now sets `max_read_bytes: 1048576`. Corpus → ClickHouse now takes 2.7–4.3 s (3.4 s in final-check).
- tests/e2e/alerts.sh gains `--spike-only` (T-AL5 only).
- tests/e2e/cli.sh: the window starts when the script starts instead of 15 min back. A benchmark (≈290k requests) had pushed `logs search` past `--limit 100000`. The wait is now on this run's demo blocks, not on blocks from any time in the last 15 min.
- Docs: NEW docs/aws-export.md (Italian: mapping, lossy, manual steps, validation, manual Terraform apply). NEW CHANGELOG.md (0.1.0 per phase). README gains the AWS export, IP lists/GeoIP and final acceptance sections plus map and docs entries. docs/performance.md has the final G-PERF results. tests/README.md updated.
- **G-PERF** (bench.sh ×3, full stack, commit 936bbfa), medians:
  - GET 5151 rps, p99 3.21 ms;
  - POST 4409 rps, p99 3.62 ms;
  - RSS 57–59 MB;
  - every D29 threshold met.
- **G-U65:** `make final-check` gives 8 × `G-FINAL step N OK`: corpus 67/67, legit 12 passed, 67 events in 3.4 s, 31 panel queries, report 30 KB, AWS export, bypass, alert after 210 s, shop18.tf VALID with lossy=xff.
- **Regression:**
  - ALL PASS: smoke, apply, joinlog, central, cli ×3, metrics, grafana, ratelimit, pki, multinode ×3.
  - The first multinode run FAILED 4: waf2-vector was still running the old config while the file changed. Then 3 consecutive ALL PASS.
  - make test-unit: 0 FAIL.

## P6 closure — PHASE 6 DONE (27-11-2026 UTC, agent-1:opus)
- **Phase fix (T-AL5 flakiness).** A back-to-back final-check failed at step 7. Grafana's log showed the block-spike alerts reaching the notifier, but no notification went out.
  - Cause: the previous spike's demo group had resolved and fired again within group_interval, with no "resolved" notification sent in between. Alertmanager dedups that until repeat_interval (4h). The first hypothesis (group_interval delaying the next notification) was wrong; the fire window extension to 7 min stays as harmless margin.
  - Fix in tests/e2e/alerts.sh: before the spike, wait until demo is Normal AND the last demo notification in alert-sink is "resolved" (max 12 min).
  - docs/dashboards-alerts.md explains this operational case.
- **Self-review against the phase scope:**
  - Export fidelity: every row of the condition→statement table and every managed/rate/custom shape is covered by TestEXP1–6/TF1–3 or the fixtures. Overrides are emitted only when they differ from the catalog default; empty RuleActionOverrides and ScopeDown are omitted.
  - AWS validation: AWS CLI says VALID for all 12 lab sites plus 3 golden web ACLs and an IP set. Terraform validate + fmt says VALID for shop18, tuned, allowlist and 4 fixtures.
  - Lossy reporting: Compat reasons plus shadow+default-block. Without --allow-lossy the export exits 2 with the list; with it, the reasons appear in `lossy` and as HCL comments.
  - List safety: validate-all-before-install, the 50 % guard, tmp+rename, custom-reputation never overwritten, offline → kept rc 0.
  - Docs: aws-export.md, operations.md, multi-node.md, README, CHANGELOG, tests/README.
- **G-P6:** `make test-unit` 16 ok, then `make final-check` 8 × G-FINAL step N OK (events in 6.0 s, alert after 180 s, shop18.tf VALID with lossy=xff).

## 27-11-2026 PLAN/1 STATE compaction (moved detail)
§2 Readiness: READY rev 1. agent-1 validated all 7 phase files, 39 sub-phases, the dependencies and the gate registry against the quality checklist ("Plan readiness"). Open questions: none. Required unverified claims: none. R1, R3, R5-addendum and R6-residual are `ACCEPTED (autonomous)` with guards (overview).

§10 Do-not-repeat at PLAN close:
- Do not put site grp/act/path-override vars in phase 1. Site-file rules run BEFORE main rules in every phase (R2 re-probe, `/tmp/pevo`), so main defaults would overwrite them.
- Do not write the audit log inside the container overlay fs (R8: 10× slower). Always use the bind-mounted `/var/log/waf`.
- Do not use go-ftw (D24). Do not use the Grafana `toJson`/`ternary` template funcs (R6).
- Do not expect `aws wafv2 get-web-acl` / `describe-managed-rule-group` to work: IAM `enforce-mfa` explicit deny. Optional R1 check (not a gate): `aws sts get-session-token --serial-number <mfa-arn> --token-code <otp>`, export the creds, then run `scripts/fetch-aws-rulegroups.sh`. If priorities differ, reorder the catalog groups (plan revision).
- Do not let an expired CRL stay on the ingress: nginx then rejects every node (R10).
- Do not expect `nginx -s reload` to reopen the ModSecurity audit log (handles keyed by path survive reloads); rotation flips the audit slot (1.7). `nginx -s reload` is asynchronous: wait on `127.0.0.1:8090/__rev` (1.5).
- Do not log `$request_method` (GET after the error_page redirect of a block); use `$waf_method` (1.7).
- Grafana file provisioning expands `$NAME` in contact-point settings: write `$$` (4.3).
- Grafana custom `allValue` is inserted verbatim (no :format): quote it in the value (4.2).
- A changed nginx `listen` address cannot be reloaded (EADDRINUSE): restart the waf container (4.1).
- Do not rename the node Vector file source id: a new id has no checkpoint and re-reads the current logs (duplicate events, P3 review).
- libmodsecurity 3 `@ipMatch` rejects an IPv6 `/128` (nginx -t "Rules error"): render full-length prefixes as bare addresses (6.3, `render/conds.go ipMatchList`).
- Do not drop the node Vector file source `max_read_bytes: 1048576`: the 2048 B default delays bursts with audit bodies by about 7 s (G-FINAL step 3, 6.5).
- Grafana/Alertmanager dedups a group that resolved and re-fired within group_interval (no "resolved" sent in between) until repeat_interval 4h. T-AL5 waits for the demo "resolved" notification before the spike (6.5/P6).
- Vector 0.62 (3.1): `${VAR}` in config needs VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true; the `vector` sink needs an `http://` address (no scheme = TLS); `geoip` table rejects Country DBs → `type: mmdb`; idle file sources back off up to ~8 s each → node reads access+audit with ONE file source and the join uses `max_events: 2`.

## 27-11-2026 PLAN/1 complete (commit below)
- **Gates:**
  - G-FINAL: `make final-check` gives 8 × `G-FINAL step N OK` on HEAD 4839dea + the P6 fix, the tree committed as 49bacd7. Corpus 67/67, legit 12 passed, 67 events in ClickHouse in 6.0 s, 31 dashboard queries OK, report 30 KB self-contained, AWS log export 396918 lines all with requestId, bypass (attack 404 + shadow_action=BLOCK, 403 after clear), block spike alert delivered after 180 s, shop18.tf VALID with lossy only `client_ip.source=xff`.
  - G-PERF: `scripts/bench.sh` exit 0. GET 5277 rps with p99 2.80 ms; POST 4596 rps with p99 3.07 ms; RSS 70–72 MB.
  - G-SEC: nothing secret is staged or tracked (no .key/.pem/secrets.env/tokens/tfstate/tfvars).
  - make test-unit: 16 packages ok.
- **Checks:** every phase P0–P6 is DONE with no SKIPPED unit. The README obligations are met. No open corrections, audits or blockers.
- **Final review (agent-1:opus, self-review).** The reference scenario is reproduced end to end on the lab. The plan's goal is met:
  - one-click ACL simulation with per-rule Count, aws-compatible/nginx-only classification, Odoo profiles;
  - full observability: ClickHouse, CLI, HTML report, Grafana with apprise alerts;
  - multi-node mTLS with PKI lifecycle;
  - AWS export to JSON/Terraform validated offline;
  - IP list maintenance.
- **Residual risks (accepted, documented):**
  - R1: managed group priorities are unverified because of the IAM MFA deny. An optional check exists.
  - AWS-proprietary patterns are approximated, with fidelity marked per rule.
  - CVE-2025-55182 pattern approximate.
  - Rate limiting is a leaky bucket, not a sliding window (D14).
  - The geoip timer needs a MaxMind account.
  - The ingest-lag alert also fires on idle lab sites (documented).
- STATE compacted to its final form.

## 27-11-2026 V001/1 complete (audit commit)
Gates: all registry gates run on 2d33b11 (results in verify_001); multinode FAILED 4 after pki.sh → V001-F1. Review: agent-1:opus. Verdict FAIL (1 MAJOR, 1 MINOR). Corrections V001-C1 (reopens phase 5), V001-C2.

## 27-11-2026 V001-C1/1 complete (commit below)
Gates:
- TestCRL1_PublishRefusesForeignCA PASS. Negative check: without the fix it FAILs with "foreign CRL: changed=true".
- TestING1_ PASS.
- tests/e2e/pki-isolation.sh ALL PASS (4).
- multinode.sh ALL PASS in the same session after pki.sh.

Review: agent-1:opus self-review.

Changes:
- wafctl/internal/central/ingress.go: PublishCRL checks the CRL signature against ingress/certs/ca.pem.
- NEW ingress_crl_test.go.
- tests/e2e/pki.sh: WAF_DATA_DIR and WAF_CENTRAL_DIR are now throwaway.
- NEW tests/e2e/pki-isolation.sh.
- docs/multi-node.md.

Notes:
- Gate registry (non-weakening): G-U51 adds TestCRL1_ and pki-isolation.sh; G-P5 adds pki-isolation.sh before multinode.
- Phase 5 reopened (attempt 2); PLAN back to TODO (attempt 2).

## 27-11-2026 V001-C2/1 complete (commit below)
- **Note on 3.3/1 (V001-F2):**
  - The closure commit of 3.3/1 is 925b6c9.
  - 9c43de8 ("align test names with G-U32/G-U33 regexes") is a follow-up within the same attempt, limited to renaming tests: TestTX[12]_ → TestX[12]_, and a TestQ3_ duplicate → TestQR1_.
  - Its repeated `PEV-Result: complete` trailer does not denote a second closure.
- **Note on history.md:** the two G-U32/G-U33 evidence lines of the 3.2/3.3 entries were rewritten in place by that commit. The original text named TestTX1_/TestTX2_ and "TestQ3_ (×2)", and is visible with `git show 9c43de8`.
- Git history is not rewritten.

## 27-11-2026 P5/2 complete (commit below)
Gates: G-P5 (amended): make test-unit ok; lab-up ok; pki-isolation.sh ALL PASS; multinode.sh ALL PASS; bootstrap.sh ALL PASS; tf-validate Success; G-SEC empty (tree + history). Review: agent-1:opus — V001-C1 meets its local contract (guard + isolation + doc), no regressions in phase 5. Changes: plan records only.
