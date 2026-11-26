# nginx AWS WAF simulator/production WAF — Plan overview

Authored 26-11-2026 by agent-1 (opus, supervisor, full autonomy). Folder: `docs/plans/001_plan-nginx-aws-waf/`.
Execution starts at [STATE.md](STATE.md); all live readiness and progress are there.
Verified artifacts referenced by phase files live in [snippets/](snippets/) (plan material, copied into the repo by the units that own them).

## Goal and reference scenario

Build, in repo `/home/fabio/Scrivania/nginx_aws_waf`, a WAF that reproduces the AWS WAF "one-click" ALB web ACL
(`AWSManagedRulesAmazonIpReputationList` → `AWSManagedRulesCommonRuleSet` → `AWSManagedRulesKnownBadInputsRuleSet`)
on nginx + ModSecurity v3 in Docker. It serves two uses: a tuning lab before going to AWS, and the production WAF
for about 20 EC2 nodes running nginx without an ALB. It must provide:
- per-rule AWS-style Count/Block/Allow overrides, scope-down, label rules and tuning profiles. Each tuning element is marked `aws-compatible` or `nginx-only`;
- full logs (bodies included), ClickHouse analytics, Grafana dashboards with apprise alerts, the `wafctl` CLI and HTML reports;
- multi-node push to a central node over mTLS;
- export to AWS (JSON or Terraform).

**Reference scenario (G-FINAL):** on the lab VM, `make lab-up` starts four sites: Odoo 12, 14, 16 and 18, with a WAF node and the central stack in all-in-one mode. Then:
1. `wafctl test run --suite tests/corpus` → every case passes. Each attack is blocked by the expected AWS rule (403, AWS-like page). Clean requests pass.
2. `make lab-legit` (Playwright) → 0 blocks on the sites using the profiles `odoo-12|14|16|18`.
3. Within 10 s the events are in ClickHouse. `wafctl stats --since 15m` shows them, and so does the Grafana "WAF Overview" dashboard.
4. `wafctl report --html --since 1h -o r.html` produces a self-contained file.
5. `wafctl logs export --from … --to … --format aws` writes AWS WAF log-format JSON lines.
6. `wafctl bypass shop18 --ttl 10m` makes attacks pass, logged with `shadow_action=BLOCK`.
7. An alert fires in apprise when blocks spike.
8. `wafctl export-aws --site shop18 --format terraform --allow-lossy` produces HCL that passes `terraform validate`. The lossy list is only `client_ip.source=xff`, a lab artefact.

**Exclusions:** CAPTCHA and Challenge actions; Bot Control, ATP and ACFP; AWS-proprietary patterns (they are approximated, fidelity marked per rule); applying Terraform; GitOps.

## Decisions
| ID | Decision and consequence | Authority/source | Supersedes |
|----|--------------------------|------------------|------------|
| D1 | Engine: `owasp/modsecurity-crs:4.30.0-nginx-alpine-202611190211` (nginx 1.30.7, libmodsecurity 3.0.17 with maxminddb, headers_more), used only as engine runtime. CRS rules are NOT loaded; our own ruleset is. | user (brainstorm) | — |
| D2 | Rules detect, an evaluator decides. All rules run in phase:2 in AWS order. Each rule R with base id B has detectors `B+0..B+6`, label rule `B+7`, terminate-candidate `B+8` and AWS-default `B+9`. Final evaluator `1900800–1900930`. Format exactly as in `snippets/reference-render.py` (verified). | user + agent-1 probe R2 | — |
| D3 | A rule catalog YAML (`waf/catalog/rules.yaml`, content = `snippets/catalog-rules.yaml`) is the single source for rendering, docs, export and tests. | autonomous (agent-1, 26-11: options hand-written .conf vs generated; generated chosen to remove ~180 boilerplate rules per change; risk = renderer bug → guard golden tests T-R*; reversal = commit rendered .conf) | — |
| D4 | One node-wide ruleset (`main.conf`, http level) plus a per-site vars file (server level: identity vars in phase 1, group/action vars and path overrides in phase 2). Per-site logic that needs labels (custom, label and scope-down rules) lives in `main.conf` after the groups, gated by `TX:site`. Verified (R2): within each phase, site-file rules run BEFORE all main rules, so a site-file rule can never see labels. | user + probe R2 | — |
| D5 | Managed group order is fixed: iprep → anonip(opt) → crs → kbi → sqli(opt). Custom rules are placed in slots `start`, `after:<GroupName>`. | autonomous (agent-1: free per-site priority would need a per-site ruleset; slots cover the one-click ACL plus custom rules; risk = an AWS ACL with a custom rule between rules of the same group cannot be expressed (AWS forbids that too); reversal = per-vhost ruleset option) | — |
| D6 | Client IP comes from nginx `realip` (`set_real_ip_from` trusted proxies + `X-Forwarded-For`), and ModSecurity `REMOTE_ADDR` follows it (verified). `client_ip.source: remote_addr` is the default (aws-compatible). `xff` is nginx-only. The lab uses xff with trusted 0.0.0.0/0, ::/0. | autonomous (agent-1: simpler than TX:client_ip parsing; reversal trivial) | brainstorm "test mode XFF" |
| D7 | `_URIPATH` detectors use `TX:raw_path` (path part of `REQUEST_URI_RAW`, set by 1900003). Pattern rules add `t:urlDecodeUni`. Size rules use the raw length. | autonomous (agent-1: closes spec open item 4) | rules-spec §7.4 |
| D8 | Body inspection is 8192 B by default. `body_limit` ∈ {8192,16384,32768,49152,65536} is aws-compatible (ALB allows 8–64 KB, R5); any other value up to 1 MiB is nginx-only. `SizeRestrictions_BODY` stays fixed at > 8192, as in AWS. | AWS doc R5 | brainstorm "8KB fixed" |
| D9 | `ctl:forceRequestBodyVariable=On` is set on every request, so REQUEST_BODY holds the raw body for urlencoded, JSON, XML and multipart (verified). `_BODY` rules inspect REQUEST_BODY. | probe R2 | — |
| D10 | Fail modes, configurable per site: `fail.pcre_limit` closed(500, default)/block(403)/open; `fail.body_error` open(default)/closed/block. A ModSecurity internal error is always 500 (fail-closed like ALB, not configurable: the connector has no hook). A rule-load failure keeps the previous config (staged `nginx -t` + atomic symlink swap). Fail actions apply only in mode `enforce`. | user (closed default) + autonomous (agent-1: internal-error option dropped, no mechanism; risk low) | brainstorm "engine error configurable" |
| D11 | Site modes: `enforce` and `count` (shadow). `wafctl bypass` forces `count` with a TTL, kept in `state/bypass.yaml`; it expires via a systemd timer that runs `wafctl bypass expire`. The evaluator never denies outside `enforce`. Logs always carry `shadow_action` (the would-be outcome). | user | — |
| D12 | Labels: hit vars `tx.hit_B`; label vars `tx.lbl_B` (and `tx.ns_<groupkey>`) are set only when in scope and no terminating rule came earlier. Label rules match `TX:lbl_B`/`TX:ns_*`. Post-terminating = logdata `tb` ≠ 0 and ≠ own id (verified in Vector). | probe R2/R7 | — |
| D13 | Custom-rule DSL (aws-compatible): `all:` AND list of conditions `label`, `label_namespace`, `uri_path`, `method`, `header`, `query_arg`, `ip_set`, `geo`, `size`, each with optional `negate`. Actions block/allow/count. OR = several rules. nginx-only extras: `path_overrides` (per-path rule action, phase-2 site file), `body_limit` outside the AWS set, `client_ip.source: xff`, `fail.*` other than the defaults, `audit.scope: relevant`. | autonomous (agent-1: minimal AWS-exportable subset; reversal: extend DSL) | — |
| D14 | Rate-based rules use nginx `limit_req` (Count = `limit_req_dry_run`, verified), keyed by client IP, rate = limit/window, burst = limit, status 403. ≈ fidelity: leaky bucket, not a sliding window; runs outside the ModSecurity order. Exported as `RateBasedStatement`. | autonomous (agent-1: ModSecurity v3 persistent collections are unreliable; risk documented) | — |
| D15 | Geo uses ModSecurity `SecGeoLookupDb` + `@geoLookup` → `tx.geo_cc` (verified). Rendered only when `node.yaml geoip.enabled` and the mmdb file exists. Vector enriches logs with GeoLite2 Country and ASN (mmdb enrichment tables). Lab and CI use the MaxMind test mmdb. | user + probe | — |
| D16 | Logs: nginx JSON access log (`snippets/nginx-probe.conf` format) + ModSecurity JSON Serial audit log (parts ABCFHZ, `SecAuditEngine On`) on a bind-mounted dir (an overlay fs slowed it ×10, R8). Vector `reduce` joins them by `$request_id` = `modsecurity_transaction_id`. The same id goes upstream as `X-Request-ID`. | user + probe R7/R8 | — |
| D17 | The joined JSON log (Vector + `raw_file` sink `events.jsonl`/`matches.jsonl`) is delivered in phase 1. The phase-2 lab matrix runs `clickhouse local` over the JSONL. The ClickHouse server, sinks and `wafctl logs` come in phase 3. | autonomous (agent-1: keeps the user's phase order without a duplicate parser) | — |
| D18 | `wafctl` (Go 1.27, module `nginxawswaf/wafctl`, the only dependency is `gopkg.in/yaml.v3`) is built in phase 0 (skeleton + catalog), phase 1 (validate/render/diff/apply/explain/bypass/test), phase 3 (logs/stats/report), phase 5 (pki/node) and phase 6 (export-aws/lists). It reaches ClickHouse over the HTTP interface (no driver) and uses `clickhouse local` in Docker for offline raw JSON. | user + autonomous (agent-1: render needed in phase 1; stdlib to keep deps minimal) | brainstorm "wafctl in phase 3" |
| D19 | Paths. Product: `$WAF_HOME` (this repo). Node config (git repo per node): `$WAF_CONFIG_DIR` (`node.yaml`, `sites/`, `profiles/`, `state/`). Data: `$WAF_DATA_DIR` (`runtime/<rev>`, `runtime/current`, `lists/`, `logs/`, `raw/`, `certs/<site>/`, `geoip/`, `vector/`). Container mounts: `runtime`→`/etc/waf/runtime`, `lists`→`/etc/waf/lists`, `logs`→`/var/log/waf`, `certs`→`/etc/waf/certs`, `geoip`→`/etc/waf/geoip`. Certificates and keys never go in git. | autonomous (agent-1) | — |
| D20 | nginx is started with `-c /etc/waf/runtime/current/nginx/nginx.conf`. A render writes `runtime/<rev>/` with absolute paths into its own rev dir. Apply = render → `nginx -t -c …/<rev>/…` inside the running container → `ln -sfn` + `mv -T` swap → `nginx -s reload`. The last 5 revs are kept. | autonomous (agent-1) | — |
| D21 | Production waf container: `network_mode: host`, master as root, workers as `nginx`, listening 80/443, IPv4+IPv6. Lab: bridge network, ports 8080/8443 published, xff trusted. | autonomous (agent-1: Docker's userland proxy hides real IPv6 client IPs, which breaks IP reputation; reversal: bridge + ip6tables) | — |
| D22 | ALB-like limits: `large_client_header_buffers 4 16k`; `client_max_body_size` per site (default 100m). Block page = AWS default 403 HTML + header `Server: awselb/2.0` (headers_more) in an internal location with `modsecurity off`. | autonomous (agent-1: without it a > 8 KB cookie got a 400 before the WAF, R2) | — |
| D23 | Rule ID map: groups 1100000/1450000/1200000/1300000/1400000 (catalog); group skip 1G00001; custom rules `1500000 + siteIdx*1000 + ruleIdx*10`; scope-down `1600000 + siteIdx*100 + groupIdx*10 (+0,+1)`; path overrides `1700000 + siteIdx*100 + i`; engine 1900001–1900099; site vars `1910000 + siteIdx*10 + k`; evaluator 1900800–1900930. siteIdx = index in the sorted site_id list (max 100 sites per node); ruleIdx < 100. | autonomous (agent-1) | rules-spec §2 ranges |
| D24 | Tests: Go unit + golden tests; `wafctl test run` corpus (YAML cases asserting the status and the terminating rule read from the audit log by an `X-Waf-Test` id); Playwright legit flows; nuclei/nikto attack generators (reported, not asserted per rule). go-ftw dropped: it asserts on the error log, which our nolog/auditlog rules do not write. | autonomous (agent-1: reversal = add a go-ftw export) | brainstorm "go-ftw" |
| D25 | Observability: ClickHouse 26.8 LTS (`clickhouse/clickhouse-server:26.8-alpine`) holds events/matches (30 d TTL), 1-minute aggregates (400 d) and heartbeats; DDL = `snippets/clickhouse-ddl.sql`. Prometheus v3.16.0 covers technical health only: node Vector `host_metrics` + `nginx_metrics` + `internal_metrics` are pushed to the central Vector `prometheus_exporter`, plus ClickHouse `:9363`. Grafana 13.2.7 with `grafana-clickhouse-datasource` 4.24.0, admin-only local users. Alerts go Grafana webhook → apprise-api 2.2.0 (`snippets/grafana-contact-point.yaml`, verified). | user + autonomous (versions) | — |
| D26 | Multi-node transport: node Vector (`vector` sink, TLS client cert) → central nginx `stream` mTLS ingress with `ssl_crl` on :6000 → central Vector `vector` source (plain TCP on the internal network). PKI is in Go (`wafctl pki init/issue/revoke/list/crl/token/serve/renew`): ECDSA P-256 keys, CA valid 10 y, leaf certs 90 d, auto-renew 30 d before expiry through `wafctl pki serve` (HTTPS mTLS on :6001 `/renew`; `/enroll` with a one-time token). | autonomous (agent-1: Vector has no CRL support; nginx stream does) | — |
| D27 | Odoo profiles are aws-compatible: rule → count + label rule that blocks outside allowed path prefixes. Initial content is in phase 2; the lab results refine it (0 legit blocks, every corpus attack blocked or listed in an explicit exception list). | user | — |
| D28 | AWS export: `wafctl export-aws --site S --format json|terraform`. JSON = `wafv2 CreateWebACL` input, validated offline with the local AWS CLI parameter validation (R11). Terraform = `aws_wafv2_web_acl` (+ `aws_wafv2_ip_set`), validated with `hashicorp/terraform` in Docker. nginx-only features → error, or warning plus omission with `--allow-lossy`. | autonomous (agent-1) | — |
| D29 | Performance targets (lab VM, 2 workers, full ruleset, full audit log, bind-mounted logs, `oha` c=8, 10 s): JSON 350 B POST ≥ 3000 req/s and p99 ≤ 5 ms; GET ≥ 3500 req/s and p99 ≤ 5 ms. Measured prototype: 4231 req/s with p99 3.65 ms, and 4890 req/s with p99 3.04 ms. | autonomous (agent-1, from R8) | brainstorm "p99 < 5 ms proposal" |
| D30 | Configuration is per node, one git repo per node. Deploy with docker compose files `deploy/compose/{node,central,lab}.yml`; all-in-one = node + central. Terraform skeleton only (`terraform validate`, never apply). | user | — |

## Open questions
None. Full autonomy: residual choices are recorded as autonomous D-rows. Unverifiable AWS facts are `ACCEPTED (autonomous)` in R1/R3.

## Architecture

```
client ──► nginx (waf container) ─ realip ─ limit_req ─ ModSecurity(main.conf + site vars) ─ evaluator ─► proxy_pass upstream (Odoo)
              │ access.log (JSON)   audit.log (JSON Serial, bodies)
              ▼
         Vector (node): join by request_id → shaped event + match rows ─► raw JSONL (7 d)  ─► [phase 5: vector sink mTLS]
                                                                         └► (all-in-one/central) Vector central ─► ClickHouse
         ClickHouse: events, matches, agg_*_1m (MVs), heartbeats ◄── wafctl logs/stats/report, Grafana dashboards+alerts ─► apprise
```

- **Rendering** (`wafctl render`) reads the catalog, `node.yaml`, `sites/*.yaml` and `profiles/*.yaml`, plus bypass state, and writes `runtime/<rev>/`:
  - `nginx/nginx.conf`
  - `nginx/sites/<site>.conf`
  - `modsec/main.conf` (engine, defaults, groups, slots, evaluator)
  - `modsec/sites/<site>.conf`
  - `data/*.data`
  - `static/<site>/403.html`, `static/<site>/500.html`
  - `meta.json`, `rules-index.json`
- **Effective configuration per site.** The site merges onto its profile chain (`extends`):
  - Maps are deep-merged.
  - `rule_groups` are merged by name.
  - `custom_rules` are concatenated (profile first, unique names); `disable_custom_rules` removes entries.
  - Bypass sets the mode to `count`.
- **Evaluation within one request.** Phase 1 runs in this order:
  1. engine defaults 19000xx;
  2. raw_path;
  3. geo;
  4. site identity vars (site file, runs first within the phase, see R2).

  Phase 2 runs in this order:
  0. site group/action vars + path overrides (site file, runs before all main phase-2 rules);
  1. slot `start`;
  2. each group, preceded by its scope-down;
  3. slot `after:<group>`;
  4. evaluator.
- **Who owns what:** wafctl owns rendering and config; Vector owns log shaping; ClickHouse owns storage and retention; Grafana owns dashboards and alerts.

## Interfaces and compatibility
| Surface | Exact name/type | Default | Errors/conflicts | Compatibility |
|---------|-----------------|---------|------------------|---------------|
| Catalog | `waf/catalog/rules.yaml` v1 (groups[key,name,vendor,wcu,label_ns,optional,rules[id,name,label,default_action,fidelity,detectors[[{vars,op,t}]]]]) | — | load error names the file and the key; duplicate id/name → error | version field gates future changes |
| node.yaml | phase_02 §Local design "Config schema" | see schema | unknown key → error (strict decode) | `version: 1` |
| sites/*.yaml, profiles/*.yaml | same schema | profile `aws-default` | validate lists errors with file:path | `version: 1` |
| CLI | `wafctl <cmd>`: catalog, validate, render, diff, apply, explain, bypass, test, logs, stats, report, pki, node, lists, export-aws | env `WAF_HOME`, `WAF_CONFIG_DIR`, `WAF_DATA_DIR`, `WAF_CH_URL`, `WAF_CH_USER`, `WAF_CH_PASSWORD` | exit 0 ok, 1 runtime error, 2 usage/validation error | additive commands only |
| Joined log | `events.jsonl` / `matches.jsonl` rows = ClickHouse columns (`snippets/clickhouse-ddl.sql`) | — | malformed lines dropped by Vector (`drop_on_error`) | additive columns only |
| AWS log export | AWS WAF log JSON (formatVersion 1: timestamp, webaclId, terminatingRuleId, terminatingRuleType, action, ruleGroupList, labels, httpRequest{clientIp,country,headers,uri,args,httpVersion,httpMethod,requestId}) | — | missing fields → empty values | matches AWS doc `logging-fields.md` |
| Rule IDs | D23 | — | renderer asserts ranges | stable across releases |

## Phase map
| Logical phase | File | Sub-phase IDs | Depends on | Assignment |
|---------------|------|---------------|------------|------------|
| 0 | [phase_01.md](phase_01.md) | 0.1–0.5 | none | agent-1 |
| 1 | [phase_02.md](phase_02.md) | 1.1–1.9 | P0 | agent-1 |
| 2 | [phase_03.md](phase_03.md) | 2.1–2.5 | P1 | agent-1 |
| 3 | [phase_04.md](phase_04.md) | 3.1–3.6 | P1 (P2 for lab data) | agent-1 |
| 4 | [phase_05.md](phase_05.md) | 4.1–4.4 | P3 | agent-1 |
| 5 | [phase_06.md](phase_06.md) | 5.1–5.5 | P3 | agent-1 |
| 6 | [phase_07.md](phase_07.md) | 6.1–6.5 | P1, P3 | agent-1 |

No live status in this table.

## Reuse map
| Need | Path and symbol | Contract to preserve |
|------|-----------------|----------------------|
| IP feeds | `scripts/fetch-ip-lists.sh` (writes `data/ip-reputation/*.txt`) | one CIDR per line, `#` comments, private ranges dropped; `OUT` dir parameterised in 6.4 |
| CRS bad-bot list | `scripts/fetch-crs.sh` → `vendor/coreruleset/rules/scanners-user-agents.data` | copied (comments stripped) into `waf/data/bad-bots.data` in 0.2 |
| AWS docs | `docs/aws/*.md` | reference only |
| Rule spec | `docs/rules-spec.md` | updated in 1.9 to match the catalog and D7/D8 |
| Verified snippets | `docs/plans/001_plan-nginx-aws-waf/snippets/*` | copied verbatim where a unit says so |

## Research and evidence

Network use was authorized by the environment: tools available, the user approved web research in the brainstorm. Access date for everything: 26-11-2026.

| ID | Question / required or optional | Evidence state | Affected decisions / units / tests |
|----|---------------------------------|----------------|------------------------------------|
| R1 | Real rule-group priorities/versions of the one-click ACL (required) | ACCEPTED (autonomous) | D5, 1.3, 6.3 |
| R2 | ModSecurity v3 semantics for our engine design (required) | CONFIRMED | D2, D4, D6, D7, D9, D10, D12, D22 |
| R3 | AWS proprietary patterns (required for fidelity) | ACCEPTED (autonomous) | D3, catalog fidelity column, 1.8 |
| R4 | Image/tool versions (required) | CONFIRMED | all compose units |
| R5 | ALB body inspection limit (required) | CONFIRMED | D8 |
| R6 | Grafana webhook → apprise payload (required) | CONFIRMED | D25, 4.3 |
| R7 | Vector join + VRL shaping + ClickHouse insert (required) | CONFIRMED | D16, D17, 1.7, 3.1 |
| R8 | Throughput / latency of the ruleset (required) | CONFIRMED | D16, D29, 1.8 |
| R9 | Odoo CLI options across versions (required) | CONFIRMED | 2.1 |
| R10 | Vector gRPC through nginx stream mTLS + CRL (required) | CONFIRMED | D26, 5.2, 5.3 |
| R11 | Offline validation of CreateWebACL input (required) | CONFIRMED | D28, 6.2 |

### R1 — one-click ACL priorities
- Sources: `docs/aws/alb-waf-integration.md`, `managed-rules-baseline.md`; `aws wafv2 get-web-acl` was blocked by the IAM `enforce-mfa` explicit deny.
- Applicability: AWS WAFv2, docs as of 26-11-2026.
- Documented fact: the one-click integration creates the three groups; their priorities are not documented.
- Supervisor inference: the order IpReputation → Common → KnownBadInputs is the order AWS lists them and the usual console order.
- Local check: not possible without an MFA session.
- Decision impact: group order is a catalog constant; changing it means reordering catalog groups (one-line change).
- Unresolved/replacement: ACCEPTED (autonomous) — agent-1, 26-11-2026. Risk: a different rule wins when several groups match (labels and blocks are unaffected). Guard: corpus case `first-wins` documents the order. Reversal: reorder the catalog after running `scripts/fetch-aws-rulegroups.sh` with MFA (STATE §10 note).

### R2 — ModSecurity v3 engine semantics
- Sources: local probes in containers of the D1 image (`/tmp/pev3`, `/tmp/pev4`, `/tmp/pevr`; artifacts in `snippets/reference-render.py`, `reference-cases.py`).
- Applicability: libmodsecurity 3.0.17, ModSecurity-nginx in the D1 image.
- Local check results:
  - http-level rules plus server-level rules (re-probed 26-11-2026, `/tmp/pevo`): **within each phase, the server-level (site) rules run BEFORE the http-level (main) rules.** Consequences:
    - an unconditional main phase-1 `setvar` overwrites a site phase-1 value;
    - a site phase-2 `SecAction` runs after all main phase-1 rules and before the first main phase-2 rule.
    - Therefore the site file sets `tx.site/mode/default_action/fail_*` in phase 1 (main 1900001 is conditional on `&TX:site`), and sets `grp_*`, `act_*` and path overrides in phase 2 (they override the unconditional main phase-1 defaults 1900010+gi). This supersedes an earlier note that claimed the opposite order.
  - Server-level `SecRequestBodyLimit` overrides the http level.
  - Log files on a bind mount: with the nginx master running as root and `SecAuditLogFileMode 0644`, `access.log`, `error.log` and `audit.log` are created root-owned 0644 and stay readable from the host (re-probed 26-11-2026). `listen [::]:<port>` works inside a bridge-network container.
  - `setvar:'tx.x=%{tx.y}'` works; an empty value in setvar is a parse error.
  - Chain continuation lines must not be indented. A chained `SecRule` needs an action string (`"t:none"`), otherwise nginx reports "Expecting an action".
  - `setvar` on the chain starter runs even if the chain fails, so the `hit` setvar must be on the LAST link.
  - logdata macros expand at match time (`tb` shows the earlier terminating rule).
  - `nolog,auditlog` puts messages in the audit log only.
  - `@ipMatchFromFile` accepts comments-only files and IPv6.
  - `@geoLookup` works with mmdb.
  - realip changes REMOTE_ADDR.
  - `ctl:forceRequestBodyVariable=On` fills REQUEST_BODY for multipart. REQBODY_ERROR is set on bad multipart.
  - The PCRE limit sets `TX:MSC_PCRE_LIMITS_EXCEEDED`.
  - A location with `return` skips rule evaluation, so a proxied location is needed.
  - nginx returns 400 for > 8 KB headers by default and 414 for ~9 KB URIs.
  - All corpus cases in `reference-cases.py` pass (after fixing test-side issues: `-g` for curl globbing, a non-escaping traversal path, the Tor IP picker) with the reference renderer.
- Decision impact: D2, D4, D6, D7, D9, D10, D12, D22.
- Unresolved: none.

### R3 — AWS proprietary patterns
- Sources: `docs/aws/managed-rules-baseline.md`, `managed-rules-use-case.md` (rule names, labels, descriptions, examples); CRS 4.30.0 rule sources.
- Documented fact: AWS publishes only descriptions and examples.
- Supervisor inference: the detectors in `snippets/catalog-rules.yaml` approximate them (fidelity `exact|approx|stub`). The ReactJSRCE pattern rests on public indicators only.
- Decision impact: the catalog content, plus corpus cases per rule.
- Unresolved: ACCEPTED (autonomous) — agent-1, 26-11-2026. Risk: FP/FN differences from AWS. Guard: the lab matrix (2.4) and the documented fidelity. Reversal: tune detectors in the catalog.

### R4 — versions
Docker Hub and GitHub API, checked 26-11-2026:
- `timberio/vector:0.62.0-alpine`
- `clickhouse/clickhouse-server:26.8-alpine` (26.8.48.11, run locally)
- `grafana/grafana:13.2.7` (run locally)
- `caronc/apprise:2.2.0`
- `prom/prometheus:v3.16.0`
- `maxmindinc/geoipupdate:v8.0.0`
- `odoo:12|14|16|18`
- `postgres:12|13|15|16`
- `golang:1.27-alpine`; local Go is 1.27.3
- `mcr.microsoft.com/playwright:v1.65.1-noble`
- `projectdiscovery/nuclei:v3.11`
- nikto 2.6.1 (git tag)
- `oha` 1.16.0 at `~/.cargo/bin/oha`
- `grafana-clickhouse-datasource` 4.24.0

Decision impact: pinned in compose files.

### R5 — ALB body limit
- Source: `docs/aws/body-inspection-limit.md` lines 12 and 24: "For Application Load Balancer, the default limit is 8 KB …, and you can increase the limit up to 64 KB (8/16/32/48/64)".
- Decision impact: D8.
- Addendum (local check, 26-11-2026): the local botocore wafv2 model (aws-cli 2.35.21) `AssociatedResourceType` enum has no ALB value. Its `RequestBodyAssociatedResourceTypeConfig` doc still says "For Application Load Balancer and AppSync, the limit is fixed at 8 KB". So the API model lags the user guide, or the ALB setting lives outside `AssociationConfig`. Consequence for D28: `export-aws` never writes an ALB `AssociationConfig`. A `body_limit` in the AWS set is emitted as a `manual_steps` entry ("set the ALB body inspection limit to N KB"), and stays aws-compatible per the user guide. ACCEPTED (autonomous); reversal: emit `AssociationConfig` once the model gains the ALB value.

### R10 — mTLS ingest through nginx stream with CRL
- Local check (26-11-2026, `/tmp/pevt`, D1 image + Vector 0.62): node Vector `vector` sink with TLS client cert → nginx stream (`ssl_alpn h2`, `ssl_verify_client on`, `ssl_crl`) → central Vector `vector` source. The valid cert delivered events; the revoked cert was rejected with `certificate revoked`. Artifact: `snippets/ingress-stream-probe.conf`.
- Caveat: nginx rejects every client when the CRL is past `next_update`, so the CRL is regenerated daily with a 7-day validity.
- Decision impact: D26, 5.2, 5.3.

### R11 — offline validation of the AWS export
- Local check: `aws wafv2 create-web-acl --cli-input-json file://x.json --endpoint-url http://127.0.0.1:9 --region eu-central-1`, run with dummy credentials and `AWS_CONFIG_FILE=/dev/null`. A valid input exits 255 (`Could not connect to the endpoint URL`); an invalid input exits 252 (`ParamValidation`). No network or AWS account is needed.
- Decision impact: D28 (replaces the planned Python botocore call), 6.2.

### R6 — Grafana → apprise
- Local check: Grafana 13.2.7 with a provisioned webhook receiver. The test API (`/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers/<uid>/test`) delivered a JSON body to an echo server.
- Finding: `toJson` and `ternary` are undefined; `coll.Dict … | data.ToJSON` works.
- Apprise `POST /notify/{KEY}` accepts `title`, `body`, `type`, `tag` (README, `/tmp/apprise-api.md`).
- Unresolved: alert-rule provisioning against the ClickHouse datasource was not run locally. Guard: gate G-P4 asserts the rules are loaded with health `ok`, plus a forced firing test. ACCEPTED (autonomous).

### R7 — Vector pipeline
- Local check: `snippets/vector-node.yaml` + `snippets/clickhouse-ddl.sql` with real nginx/ModSecurity logs (6 requests).
- Result: all 6 events were joined. The action, terminating rule and type, AWS-default outcome, labels, post_terminating and user_class values were correct. The MVs aggregated. The `raw_file` sink was written.
- Notes:
  - VRL `if` is not an expression inside object literals; assign variables first.
  - `to_int(x) ?? 0` on an infallible input is a compile error (E651); wrap it as `to_int(string(x) ?? "0") ?? 0`.
  - `validate --no-environment` checks the config offline.

### R8 — performance
- Local check: `oha` against nginx with 2 workers and the full catalog plus audit log on tmpfs:
  - 350 B JSON POST: 4231 req/s, p99 3.65 ms;
  - GET: 4890 req/s, p99 3.04 ms;
  - audit `RelevantOnly`: ≈ same.
- With the audit log on the container overlay fs growing to more than 100 MB: 1.6k req/s with p99 57 ms.
- An empty ruleset gives 8.5k req/s.
- Decision impact: D16 (bind mount), D29.

### R9 — Odoo
- Local check: `odoo --help` in `odoo:12` and `odoo:18` lists `--proxy-mode`, `--db-filter`, `--without-demo` and `--db_host`. v12 uses `--longpolling-port`, v18 uses `--gevent-port`. Real-time paths are `/longpolling` (12/14) and `/websocket` (16/18).

## Invariants
| ID | Meaning | Guarding test |
|----|---------|---------------|
| I-1 | AWS order: the first rule (catalog order + slots) whose effective action is block/allow terminates. Later matches are logged with post_terminating=1 and add no labels. | T-E1 corpus `first-wins`; golden T-R1 |
| I-2 | A rule set to count never changes the outcome but is logged and labelled. | T-E2 `count-override` cases |
| I-3 | Mode `count`/bypass never returns a WAF 403/500. `shadow_action` still shows the would-be result. | T-E3 bypass cases |
| I-4 | The aws-default outcome ignores site overrides, custom rules and scope-down. | T-E2 + Vector check in 1.7 |
| I-5 | A failed render or `nginx -t` never changes the running config. | T-A1 apply-rollback test (1.5) + `tests/e2e/apply.sh` |
| I-6 | Every inspected request produces exactly one event row joined by request_id. | T-L1 (1.7), T-C1 (3.1) |
| I-7 | All timestamps are UTC. | T-L1 asserts the `Z` suffix; DDL uses `DateTime64(3,'UTC')` |
| I-8 | Certificates/keys and secrets are never committed. | `.gitignore` check in G-BASE-style gate G-SEC |

## Risks
| Risk | Design mitigation | Verification |
|------|-------------------|--------------|
| Approximate patterns differ from AWS | fidelity column; lab matrix | 2.4 matrix report |
| Odoo FPs | count + label-rule profiles per version | 2.3 + 2.5 legit suite 0 blocks |
| Audit-log I/O cost | bind mount, rotation, `audit.scope: relevant` option | D29 benchmark gate G-PERF |
| Vector join loses events under load | reduce expire 3 s; unjoined access events are still emitted (waf_inspected=0) | T-L2 load + count check |
| ModSecurity reload memory | one ruleset; ~50 MB RSS measured | G-PERF records RSS |
| PKI misuse | CRL at nginx stream, 90-day certs, one-time tokens | 5.x tests |
| Terraform/AWS export drift | offline botocore validation | 6.3 tests |

## Verification strategy
STATE.md §3 is the gate registry:
- each unit has focused gates (G-U*);
- each phase has a gate G-P<N>;
- G-PERF runs at P1 and PLAN;
- G-FINAL runs the reference scenario through `make final-check`.

Golden render tests guard the generated ModSecurity syntax. Every renderer change must pass `nginx -t` in the D1 image (G-NGXT) before any e2e test.

## Agent-assignment summary
Executor power: low. Units are small, steps are mechanical, and complex parts reuse verified snippets. The executor decides only locators and details explicitly left open.

| Unit(s) | Implementer | Required supervisor review |
|---------|-------------|----------------------------|
| all | agent-1 (self) | agent-1 self-review at each unit close (explicitly labelled `self-review`); phase review at P<N> |
