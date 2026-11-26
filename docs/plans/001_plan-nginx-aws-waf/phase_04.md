# Phase 3 — Central storage: ClickHouse, central Vector, GeoIP enrichment, heartbeats, `wafctl logs|stats|report`

Intent: in all-in-one mode, every request lands in ClickHouse within 10 s, enriched with country and ASN. `wafctl logs search|tail|show|export`, `wafctl stats` and `wafctl report --html` work against ClickHouse, or offline over raw JSONL. Retention is configurable.
Prerequisites: P1 DONE. P2 is recommended (Odoo data), but the gates use the demo corpus only.
Phase closure: P3; review by agent-1.

## State and ownership contract
Read STATE.md §1 first (and PROTOCOL.md once without this skill) for scope, ownership, recovery, checks and commit rules. Open a unit before editing; checkpoint at a recovery boundary; close with evidence. Missing design goes to agent-1, the supervisor. Executor power: low. Follow the steps literally. SQL and VRL must start from the verified snippets.

## Local design context
Plan revision: rev 1.

**Decisions:**
- **D16/D17:** the node joins and shapes logs; central only routes, enriches and stores.
- **D18:** wafctl uses the ClickHouse HTTP interface, with parameters passed as `param_<name>` URL query parameters (never string-concatenated SQL), plus `FORMAT JSONEachRow`.
- **D25:** versions.
- **I-6, I-7.**

### Transport in this phase (TLS is added in P5)
Node Vector gets a rendered extra config `runtime/<rev>/vector/forward.yaml`:
- **When forwarding is configured:**
  ```yaml
  transforms:
    fwd_events: {type: remap, inputs: [events_out], source: '._t = "event"'}
    fwd_matches: {type: remap, inputs: [matches_out], source: '._t = "match"'}
    fwd_hb: {type: remap, inputs: [hb_parse], source: '._t = "hb"'}
  sinks:
    fwd_central:
      type: vector
      inputs: [fwd_events, fwd_matches, fwd_hb]
      address: "<central address>"
      buffer: {type: disk, max_size: 2147483648, when_full: block}
  ```
- **When not configured:** the same transforms, plus a sink `fwd_none: {type: blackhole, inputs: [fwd_events, fwd_matches, fwd_hb], print_interval_secs: 0}`.

Central address resolution (render):

| role | network | central.address | value |
|---|---|---|---|
| all-in-one | bridge | — | `vector-central:6000` |
| all-in-one | host | — | `127.0.0.1:6000` |
| node | any | set | `<central.address>:<ingest_port>` (P5 makes it TLS) |
| node | any | "" | not configured |

Heartbeat (added to `deploy/vector/node.yaml`):
```yaml
sources:
  hb_exec:
    type: exec
    mode: scheduled
    scheduled: {exec_interval_secs: 30}
    command: ["cat", "/etc/waf/runtime/current/meta.json"]
transforms:
  hb_parse:
    type: remap
    inputs: [hb_exec]
    drop_on_error: true
    source: |
      m = object!(parse_json!(string!(.message)))
      . = {"ts": format_timestamp!(now(), "%Y-%m-%dT%H:%M:%S%.3fZ", timezone: "UTC"),
           "node_id": m.node_id, "version": m.version, "config_rev": m.config_rev, "sites": m.sites}
```
**Requirement:** `meta.json` is rendered as compact single-line JSON. Change 1.3 render accordingly (`json.Marshal`, not `MarshalIndent`). The vector service mounts `${WAF_DATA_DIR}/runtime:/etc/waf/runtime:ro`. Command: `--config /etc/vector/vector.yaml --config /etc/waf/runtime/current/vector/forward.yaml`. Apply restarts vector (`docker compose restart vector`) when `vector/forward.yaml` differs from the previous current rev.

### Central compose (`deploy/compose/central.yml`, project `waf`)
- **`clickhouse`:**
  - image `clickhouse/clickhouse-server:26.8-alpine`;
  - env `CLICKHOUSE_USER=waf_admin`, `CLICKHOUSE_PASSWORD=${WAF_CH_ADMIN_PASSWORD}`, `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1`;
  - volumes:
    - `${WAF_CENTRAL_DIR}/clickhouse:/var/lib/clickhouse`
    - `../clickhouse/initdb:/docker-entrypoint-initdb.d:ro`
    - `../clickhouse/config.d/waf.xml:/etc/clickhouse-server/config.d/waf.xml:ro`
  - `ulimits nofile 262144`;
  - healthcheck `wget -qO- http://127.0.0.1:8123/ping`;
  - ports: none in bridge; `127.0.0.1:8123:8123` always, for wafctl on the host.
- **`vector-central`:**
  - image `timberio/vector:0.62.0-alpine`;
  - volumes:
    - `../vector/central.yaml:/etc/vector/vector.yaml:ro`
    - `${WAF_CENTRAL_DIR}/vector:/var/lib/vector`
    - `${WAF_DATA_DIR}/geoip:/etc/waf/geoip:ro`
  - env `WAF_CH_INGEST_PASSWORD`;
  - port `127.0.0.1:6000:6000` (all-in-one host mode). In P5 it becomes internal only, behind the ingress.
- `WAF_CENTRAL_DIR` defaults to `$WAF_DATA_DIR/central`.
- **Secrets file** `$WAF_CONFIG_DIR/secrets.env` (git-ignored via `.gitignore` in the node repo; mode 0600) holds `WAF_CH_ADMIN_PASSWORD`, `WAF_CH_INGEST_PASSWORD`, `WAF_CH_RO_PASSWORD` (and `GF_ADMIN_PASSWORD` in P4). `wafctl secrets init` generates them with 24 random bytes each, base64url. Compose is invoked with `--env-file $WAF_CONFIG_DIR/secrets.env`.

### ClickHouse files
- `deploy/clickhouse/initdb/001-schema.sql`: `snippets/clickhouse-ddl.sql` verbatim, minus the `-- VERIFIED` line.
- `deploy/clickhouse/initdb/002-users.sh`:
  ```sh
  #!/bin/bash
  set -e
  clickhouse client -n <<EOSQL
  CREATE USER IF NOT EXISTS waf_ingest IDENTIFIED WITH sha256_password BY '${WAF_CH_INGEST_PASSWORD}';
  GRANT INSERT, SELECT ON waf.* TO waf_ingest;
  CREATE USER IF NOT EXISTS waf_ro IDENTIFIED WITH sha256_password BY '${WAF_CH_RO_PASSWORD}' SETTINGS readonly = 2;
  GRANT SELECT ON waf.* TO waf_ro;
  EOSQL
  ```
  The two passwords are passed to the clickhouse service env as well. `readonly = 2` is needed because the Grafana plugin sets settings.
- `config.d/waf.xml`:
  - `<clickhouse><logger><level>warning</level></logger>`;
  - `<prometheus><endpoint>/metrics</endpoint><port>9363</port><metrics>true</metrics><events>true</events><asynchronous_metrics>true</asynchronous_metrics></prometheus>`;
  - `<max_server_memory_usage_to_ram_ratio>0.5</max_server_memory_usage_to_ram_ratio></clickhouse>`.

### Central Vector (`deploy/vector/central.yaml`)
```yaml
data_dir: /var/lib/vector
enrichment_tables:
  geo_country: {type: geoip, path: /etc/waf/geoip/GeoLite2-Country.mmdb}
  geo_asn: {type: geoip, path: /etc/waf/geoip/GeoLite2-ASN.mmdb}
sources:
  from_nodes: {type: vector, address: "0.0.0.0:6000"}
transforms:
  route_t:
    type: route
    inputs: [from_nodes]
    route:
      event: '._t == "event"'
      match: '._t == "match"'
      hb: '._t == "hb"'
  enrich:
    type: remap
    inputs: [route_t.event]
    source: |
      del(._t)
      ip = string(.client_ip) ?? ""
      c, err = get_enrichment_table_record("geo_country", {"ip": ip})
      if err == null { .country = string(c.country_code) ?? string(c.country.iso_code) ?? "" }
      a, err2 = get_enrichment_table_record("geo_asn", {"ip": ip})
      if err2 == null { .asn = to_int(a.autonomous_system_number) ?? 0; .as_org = string(a.autonomous_system_organization) ?? "" }
  m_clean: {type: remap, inputs: [route_t.match], source: 'del(._t)'}
  hb_clean: {type: remap, inputs: [route_t.hb], source: 'del(._t)'}
sinks:
  ch_events:   {<as snippets/vector-node.yaml ch_events, inputs: [enrich], endpoint: http://clickhouse:8123, auth user waf_ingest, password "${WAF_CH_INGEST_PASSWORD}">}
  ch_matches:  {<same pattern, inputs [m_clean], table matches>}
  ch_heartbeats: {<same pattern, inputs [hb_clean], table heartbeats>}
```
- Copy the `ch_events` / `ch_matches` blocks from the snippet verbatim, changing only `inputs`, `endpoint` and `auth`.
- In all-in-one host mode the endpoint is `http://127.0.0.1:8123` only if `vector-central` runs with host network. It does not: central services always use the bridge network `waf_central`, and in all-in-one bridge mode they also join `waf_lab`. Endpoint stays `http://clickhouse:8123`.
- **Geo fallback (unverified field path, guarded by T-C2):** the VRL above tries both `country_code` and `country.iso_code`. If Vector rejects the Country DB type (`Unsupported database type`), switch both the lab test file and the prod download to the City edition (`GeoLite2-City.mmdb`; test `GeoIP2-City-Test.mmdb`). Record that in §6. This is a pre-authorized fallback.

GeoIP files in `$WAF_DATA_DIR/geoip/`:
- Lab: `make geoip-test` downloads `GeoIP2-Country-Test.mmdb` and `GeoLite2-ASN-Test.mmdb` from `https://github.com/maxmind/MaxMind-DB/raw/main/test-data/` and saves them as `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb`.
- Prod: `maxmindinc/geoipupdate:v8.0.0` with `GEOIPUPDATE_EDITION_IDS="GeoLite2-Country GeoLite2-ASN"` plus account env from `secrets.env` (6.4 schedules it).

### wafctl ClickHouse access
- Env: `WAF_CH_URL` (default `http://127.0.0.1:8123`), `WAF_CH_USER` (default `waf_ro`), `WAF_CH_PASSWORD` (default: read `WAF_CH_RO_PASSWORD` from `$WAF_CONFIG_DIR/secrets.env` if present).
- `internal/ch`:
  - `Query(ctx, sql string, params map[string]string, out func(json.RawMessage) error) error` → POST `?query=…&param_x=…&default_format=JSONEachRow`, streaming the decode line by line;
  - HTTP error → the body is included in the error.
- `--raw DIR` (all read commands): offline mode via `docker run --rm -v DIR:/raw:ro clickhouse/clickhouse-server:26.8-alpine clickhouse local`, with the same SQL against the views `events` and `matches`. These are defined with `CREATE VIEW events AS SELECT * FROM file('/raw/*/events.jsonl', JSONEachRow, '<schema>')`. The schema string is generated from the embedded DDL (`go:embed` of `001-schema.sql`, parsing the column list between `(` and `)` of each CREATE TABLE). In raw mode, `agg_*` queries fall back to events.

## Sub-phases

### 3.1 Central stack + forwarding + heartbeat
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - NEW: `deploy/compose/central.yml`, `deploy/clickhouse/initdb/{001-schema.sql,002-users.sh}`, `deploy/clickhouse/config.d/waf.xml`, `deploy/vector/central.yaml`, `wafctl/internal/render/vector.go`, `wafctl/internal/secrets/secrets.go`, `tests/e2e/central.sh`.
  - WRITE: `deploy/vector/node.yaml` (heartbeat), `deploy/compose/node.yml` (vector mounts and command), `wafctl/internal/render/write.go` (compact meta.json), `wafctl/internal/apply/apply.go` (vector restart on change; compose files for the role, `--env-file`), `wafctl/internal/docker/docker.go` (env: `WAF_DATA_DIR`, `WAF_CONFIG_DIR`, `WAF_CENTRAL_DIR`, `WAF_NODE_ID`), `Makefile` (`geoip-test`, `lab-up` with role all-in-one), `lab/config/node.yaml` (role all-in-one).
- **Change:**
  - Preconditions: P1 DONE.
  - Contract: as in Local design. Compose files per role:
    - node → `node.yml` + network file;
    - central → `central.yml`;
    - all-in-one → both.
    `wafctl secrets init [--force]` writes `secrets.env` if missing.
  - Steps:
    1. S1 — The ClickHouse files.
    2. S2 — Central Vector, validated with `vector validate --no-environment` (env placeholders need `--no-environment`).
    3. S3 — Forward render, heartbeat, meta.json.
    4. S4 — Compose + apply changes.
    5. S5 — `make geoip-test lab-up`.
  - Recovery boundary: after the first ClickHouse init (data dir created). Record it in §6.
  - Failure handling:
    - the initdb scripts run only on an empty data dir. If the DDL changes later, use `wafctl ch migrate` (3.5). For the lab, `rm -rf .run/central/clickhouse` is allowed.
    - geo fallback as described above.
- **Unit tests:** T-C0: forward.yaml render for the 4 rows of the address table; meta.json is single-line. G-U31.
- **e2e tests:** `tests/e2e/central.sh`:
  1. Run the corpus with run id R.
  2. Within 10 s (poll every 1 s): `SELECT count() FROM waf.events WHERE mapContains(request_headers,'x-waf-test') AND request_headers['x-waf-test'] LIKE 'R-%'` equals the case count (T-C1, I-6). Check the header-key case in the events row first; if keys keep their original case, use `X-Waf-Test`, and record the observed form in the script comment.
  3. `matches` rows > 0.
  4. `heartbeats` has a row for `lab-node-1` newer than 60 s.
  5. T-C2: a request with xff `2.125.160.216` → `country='GB'`; xff `89.160.20.112` → `country='SE'`, and the ASN is non-zero if the ASN test DB covers it (otherwise just log it).
  6. Aggregates: `agg_requests_1m` sum(requests) for the window ≥ the case count.
  - G-U31.
- **Done:** G-U31 passes.

### 3.2 `wafctl logs search|show|tail`
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:** NEW: `wafctl/internal/ch/{ch.go,ch_test.go,raw.go,schema.go}`, `wafctl/internal/logs/{query.go,search.go,tail.go,show.go,logs_test.go}`. WRITE: `cmd/wafctl/main.go`.
- **Change:**
  - Preconditions: 3.1 DONE.
  - Contract. Common filter flags:
    - `--site S` (repeatable)
    - `--since DUR` (default 1h) | `--from RFC3339 --to RFC3339` (UTC; inputs without a zone are rejected)
    - `--action ALLOW|BLOCK|FAIL`, `--shadow BLOCK`
    - `--rule NAME` (matches `terminating_rule` suffix `/NAME`, or has(matches rule_name) when `--matched`)
    - `--ip IP`, `--country CC`, `--path-prefix P`, `--user-class C`, `--status N`, `--rid ID`
    - `--limit N` (default 100, max 100000)
    - `--format table|json`

    `query.go` builds the WHERE clause only from fixed fragments with `{name:Type}` placeholders (ClickHouse parameter syntax) plus params. Unit tests assert that no user value appears in the SQL text.
    - `logs search`: columns `TS SITE IP CC METHOD PATH STATUS ACTION SHADOW TERMINATING RID` (path truncated to 60 chars in table mode).
    - `logs show <rid>`: the full event (JSON pretty) plus its matches table `RULE GROUP ACTION INSCOPE POST VAR VALUE`.
    - `logs tail`: same filters; polls every 2 s for `ts > last_ts` (ties are deduplicated by request_id); prints new rows; stops on Ctrl-C.
  - Steps:
    1. S1 — The ch client + raw mode.
    2. S2 — The query builder.
    3. S3 — The commands.
- **Unit tests:**
  - T-Q1 (builder): filters become placeholders, and the value is absent from the SQL.
  - T-Q2: `--from` without a zone → error.
  - T-Q3: the ch client against `httptest.Server` decodes JSONEachRow and surfaces HTTP 500 bodies.
  - T-Q4: the schema parser extracts 47 events columns from the embedded DDL (count asserted against the DDL file at test time, not hard-coded).
  - G-U32.
- **e2e tests:** after the corpus run:
  - `wafctl logs search --since 10m --action BLOCK --site demo --format json | jq length` ≥ the number of blocking demo cases;
  - `logs show <one rid>` lists matches;
  - `--raw .run/raw` gives the same count (T-Q5).
  - G-U32.
- **Done:** G-U32 passes.

### 3.3 `wafctl logs export` (range export, AWS log format)
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - READ: `docs/aws/logging-fields.md` (if missing, fetch it with `scripts/fetch-aws-docs.sh`; else use the field list in the overview Interfaces row).
  - NEW: `wafctl/internal/logs/{export.go,awsfmt.go,awsfmt_test.go}`.
  - WRITE: `cmd/wafctl/main.go`.
- **Change:**
  - Preconditions: 3.2 DONE.
  - Contract: `wafctl logs export --from --to [filters] --format jsonl|csv|aws [--with-matches] [--gzip] -o FILE` (`-` = stdout). It streams and never buffers everything.
    - `jsonl`: event rows; with `--with-matches`, each row gets `matches: [...]` via a second query grouped by request_id (`groupArray(tuple(...))`, joined with `LEFT JOIN` on `request_id` within the same time window).
    - `csv`: event columns except headers and body.
    - `aws`, one JSON object per line:
      ```json
      {"timestamp": <ms epoch>, "formatVersion": 1, "webaclId": "nginx-aws-waf:<node_id>:<site_id>",
       "terminatingRuleId": "<terminating_rule name part or Default_Action>",
       "terminatingRuleType": "<terminating_type>", "action": "<action>",
       "terminatingRuleMatchDetails": [], "httpSourceName": "ALB", "httpSourceId": "<site_id>",
       "ruleGroupList": [{"ruleGroupId": "AWS#<group>", "terminatingRule": {"ruleId": "<rule>", "action": "BLOCK"} | null,
                          "nonTerminatingMatchingRules": [{"ruleId": "<rule>", "action": "COUNT"}], "excludedRules": null}],
       "rateBasedRuleList": [], "nonTerminatingMatchingRules": [],
       "requestHeadersInserted": null, "responseCodeSent": <status if action BLOCK else null>,
       "httpRequest": {"clientIp": "<ip>", "country": "<cc>", "headers": [{"name": "...", "value": "..."}],
                       "uri": "<path>", "args": "<query>", "httpVersion": "<HTTP/1.1>", "httpMethod": "<M>", "requestId": "<rid>"},
       "labels": [{"name": "<label>"}]}
      ```
      ruleGroupList holds one entry per group present in the matches. `terminatingRule` is set for the group that holds the terminating rule; other matches with configured_action COUNT go into `nonTerminatingMatchingRules`. Custom rules: when the terminating rule is custom, set `terminatingRuleId` = its name and type REGULAR.
  - Steps:
    1. S1 — `awsfmt.go` as a pure function `ToAWS(ev Event, ms []Match) AWSLog`.
    2. S2 — Export streaming.
- **Unit tests:**
  - T-X1: `ToAWS` on fixtures: a block by CommonRuleSet with a count match in KBI; a custom block; default allow. Golden JSON.
  - T-X2: csv header line exact.
  - G-U33.
- **e2e tests:** `wafctl logs export --since 15m --format aws -o /tmp/x.jsonl` → each line parses (`jq -e .httpRequest.requestId`), and the count equals the count from `logs search` for the same window. G-U33.
- **Done:** G-U33 passes.

### 3.4 `wafctl stats`
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:** NEW: `wafctl/internal/stats/{stats.go,sql.go,stats_test.go}`. WRITE: `cmd/wafctl/main.go`.
- **Change:**
  - Preconditions: 3.3 DONE.
  - Contract: `wafctl stats [--since 1h|--from/--to] [--site S] [--by overview|rule|site|path|ip|country|user_class|status] [--top 20] [--format table|json]`.
    - `overview`: requests, allow, block, fail, shadow-block, aws_default block, disagreement count, rps avg. It comes from `agg_requests_1m` when the window is ≥ 1h, else from events.
    - `rule`: from `agg_matches_1m` (≥ 1h) or matches. Columns `GROUP RULE MATCHES TERMINATING(post=0) COUNTED(configured COUNT) SITES`.
    - `path`, `ip`, `country`, `status`, `user_class`: from events, top N with block counts.
    - Tuning view `--by rule --counted`: only rules with configured_action COUNT, ordered by matches. These are the would-block candidates.
  - Steps:
    1. S1 — The SQL constants (one per view) using parameters `{since:DateTime64(3)}`, `{site:Array(String)}`. An empty site array means all, via `(empty({site:Array(String)}) OR site_id IN {site:Array(String)})`.
    2. S2 — Table rendering.
- **Unit tests:**
  - T-S1: SQL selection chooses agg vs events by window;
  - T-S2: the table renderer is golden;
  - T-S3: the `--counted` filter is in the SQL.
  - G-U34.
- **e2e tests:** after the corpus: `wafctl stats --since 15m --by rule --format json` contains `NoUserAgent_HEADER` with matches ≥ 1; `--by overview` block ≥ the blocking cases. G-U34.
- **Done:** G-U34 passes.

### 3.5 `wafctl report --html`, retention and migrations
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - NEW: `wafctl/internal/report/{report.go,svg.go,template.html,report_test.go}`, `wafctl/internal/ch/migrate.go`.
  - WRITE: `cmd/wafctl/main.go`, `deploy/systemd/` (none).
- **Change:**
  - Preconditions: 3.4 DONE.
  - Contract:
    - `wafctl report --html [--since 24h|--from/--to] [--site S] -o FILE`:
      - one self-contained HTML file built with `html/template` and embedded CSS. Charts are inline SVG made by `svg.go`: horizontal bars, plus a time series of per-hour stacked allow/block columns.
      - No external URL anywhere: T-H1 asserts no `src="http` and no `href="http` except plain text links to docs.
      - Sections, in order:
        1. Summary (overview numbers, generation time in UTC, filters);
        2. Timeline;
        3. Top terminating rules;
        4. Counted rules (would-block candidates);
        5. AWS-default disagreements (top rows);
        6. Top blocked paths;
        7. Top client IPs / countries;
        8. Fail events;
        9. Config snapshot: `meta.json` of the current rev and the per-site compat line, when run on a node with `$WAF_CONFIG_DIR`.
      - All sections reuse the `stats` SQL.
    - `wafctl ch migrate`:
      - creates the table `waf.schema_migrations(version UInt32, applied DateTime)`;
      - applies the embedded `migrations/NNN-*.sql` in order. Version 001 is the initial DDL; it is skipped when `waf.events` exists and is marked applied.
      - Runs as `waf_admin` via env `WAF_CH_ADMIN_PASSWORD`.
    - `wafctl ch retention [--raw-days N] [--agg-days M]`:
      - runs `ALTER TABLE waf.events MODIFY TTL toDateTime(ts) + INTERVAL {N} DAY`, the same on matches, and `agg_*` with M;
      - prints the current TTLs (from `system.tables.create_table_query`, extracting the `TTL` clause) when no flag is given.
      - N must be 1–3650; M must be ≥ N.
  - Steps:
    1. S1 — Report.
    2. S2 — migrate + retention.
- **Unit tests:**
  - T-H1: HTML from fixture data — no external refs; 9 section ids present.
  - T-H2: SVG bars with 0 values do not divide by zero.
  - T-M1: the migration list is ordered and 001 is detected as applied.
  - G-U35.
- **e2e tests:**
  - `wafctl report --html --since 1h -o build/r.html` → the file exists, is > 10 KB, has no external refs and contains `NoUserAgent_HEADER`;
  - `wafctl ch retention --raw-days 20` then no-arg → shows `20 DAY`; restore 30.
  - G-U35.
- **Done:** G-U35 passes.

### 3.6 Observability docs
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:** NEW: `docs/observability.md`. WRITE: `README.md` (section), `docs/operations.md` (central, secrets, retention, migrations).
- **Change:**
  - Preconditions: 3.5 DONE.
  - Contract (Italian):
    - data flow;
    - tables and columns (link to the DDL);
    - field meanings: action, shadow_action, aws_default_action, terminating_type, post_terminating, user_class;
    - example `wafctl logs/stats/report` commands;
    - the offline `--raw` mode;
    - export formats, including the AWS mapping table;
    - retention knobs: node raw days, CH raw/agg TTL;
    - the geo DB setup.
  - Steps: S1 — Write the docs.
- **Unit tests:** N/A — docs.
- **e2e tests:** N/A.
- **Done:** self-review confirms every command in the docs runs (copy-paste check on the lab). G-U36 passes.

## Phase gates and closure
- Required gates: G-U31..G-U36, then G-P3 (`make lab-up test-e2e && tests/e2e/central.sh && make test-unit`, plus the 3.2–3.5 e2e commands collected in `tests/e2e/cli.sh`, created in 3.5 S2).
- README obligation: unit 3.6.
- Every sub-phase DONE or SKIPPED with a reason. Run the full phase gates now.
- agent-1 reviews I-6/I-7, the SQL parameterisation (no injection) and the docs.
- Open P3, record the review, mark DONE. Commit `phase(001/P3): PHASE 3 COMPLETE — Central storage and CLI analytics; gates and review passed`.
