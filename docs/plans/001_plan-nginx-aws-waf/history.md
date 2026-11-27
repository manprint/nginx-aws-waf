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
- G-U32: TestQ1_, TestQ2_, TestQ3_ (×2), TestQ4_ (47 events columns, counted from the DDL) PASS; cli.sh ALL PASS (search blocks demo 531 ≥ 44, rule filter, show → 2 matches, T-Q5 raw = CH 2866 = 2866).
