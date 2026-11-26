# Phase 0 — Foundations: repo baseline, rule catalog, wafctl skeleton, config schema

Intent: the repo has a first commit, the verified rule catalog and data files are versioned, and `wafctl` builds. `wafctl catalog list` and `wafctl validate` work on an example config.
Prerequisites: none.
Phase closure: P0; review by agent-1.

## State and ownership contract
Read STATE.md §1 first (and PROTOCOL.md once without this skill) for scope, ownership, recovery, checks and commit rules. Open a unit before editing it; checkpoint at a recovery boundary; close it with evidence. A delegated worker follows its assigned OPEN unit. Missing design goes to agent-1, the supervisor. Executor power: low. Follow the steps literally; decide only file-internal naming not fixed here.

## Local design context
Plan revision: rev 1.
- D3: `waf/catalog/rules.yaml` is the single source of rules. Copy `snippets/catalog-rules.yaml` verbatim, dropping only the first `# VERIFIED` comment line.
- D18: Go module `nginxawswaf/wafctl` in `wafctl/`, Go 1.27, the only external dependency is `gopkg.in/yaml.v3 v3.0.1`. CLI built on stdlib `flag`.
- D19: env `WAF_HOME` (default: the repo root, found by walking up from cwd to the dir holding `waf/catalog/rules.yaml`), `WAF_CONFIG_DIR` (default `/etc/waf-node`), `WAF_DATA_DIR` (default `/srv/waf`).
- D13/D23: config schema below; validation rules in 0.5.
- I-8: certificates, keys, `.run/` and `build/` are never committed.

### Repository layout (created across phases; NEW dirs get a `README.md` only when a unit says so)
```
Makefile                         top-level targets (0.1, extended by later units)
waf/catalog/rules.yaml           catalog (0.2)
waf/data/*.data                  pattern files (0.2)
waf/static/403.html, 500.html    block pages (0.2)
waf/Dockerfile                   engine image (1.4)
wafctl/                          Go module (0.3+)
deploy/compose/{node,central,lab}.yml   (1.4, 3.1, 2.1)
deploy/vector/{node,central}.yaml       (1.7, 3.1)
deploy/clickhouse/initdb/001-schema.sql (3.1)
deploy/grafana/…  deploy/prometheus/…   (4.x)
deploy/systemd/*.service|*.timer        (1.5, 5.3)
deploy/terraform/…                      (5.5)
lab/config/{node.yaml,sites/,profiles/} lab node config repo (1.4, 2.1)
profiles/*.yaml                  shipped profiles (0.4, 2.2)
tests/corpus/*.yaml              attack/clean corpus (1.6)
tests/legit/                     Playwright (2.3)
tests/e2e/*.sh                   e2e scripts (various)
docs/…                           docs (1.9, 3.6, 5.5, 6.5)
```

### Config schema (version 1). Strict YAML decoding: an unknown key is an error.
`node.yaml`:
```yaml
version: 1
node_id: lab-node-1          # ^[a-z0-9][a-z0-9-]{0,62}$
role: all-in-one             # node | central | all-in-one
network: bridge              # host (prod default) | bridge (lab)
listen: {http: 8080, https: 8443, ipv6: true}   # defaults: host→80/443, bridge→8080/8443
workers: 2                   # 0 = auto
geoip: {enabled: false}      # true → /etc/waf/geoip/GeoLite2-Country.mmdb must exist
audit: {scope: all}          # all | relevant (nginx-only)
default_site: ""             # "" → unknown Host answered 444 without WAF
central: {address: "", ingest_port: 6000, pki_port: 6001}
retention: {raw_days: 7, log_hours: 24}
lab: {enabled: false}        # true allows client_ip.trusted_proxies 0.0.0.0/0
```
`sites/<site_id>.yaml` (site keys + WAF settings inline):
```yaml
version: 1
site_id: shop18                         # ^[a-z0-9][a-z0-9_-]{0,31}$ ; file name must equal site_id + .yaml
server_names: [shop18.lab.test]
app: odoo                               # odoo | generic
profile: odoo-18                        # default aws-default
upstream:
  servers: ["odoo18:8069"]
  realtime: {path: /websocket, servers: ["odoo18:8072"]}   # optional
  tls: false
  max_body_size: 100m
  read_timeout_sec: 720
tls: {mode: off}                        # off | on | redirect ; cert/key default fullchain.pem/privkey.pem in $WAF_DATA_DIR/certs/<site_id>/
# --- WAF settings (same keys allowed in profiles) ---
mode: enforce                           # enforce | count
default_action: allow                   # allow | block
body_limit: 8192
client_ip: {source: remote_addr, trusted_proxies: []}     # source: remote_addr | xff
fail: {pcre_limit: closed, body_error: open}               # closed|block|open
rule_groups:
  - name: AWSManagedRulesCommonRuleSet
    enabled: true
    override_action: none               # none | count
    rule_action_overrides: {SizeRestrictions_BODY: count}  # values block|count|allow
    scope_down: {all: [{uri_path: {starts_with: /web/}}]}
custom_rules:
  - name: BlockLargeBodyOutsideRpc
    slot: after:AWSManagedRulesCommonRuleSet   # start | after:<GroupName>
    action: block                               # block | allow | count
    match:
      all:
        - {label: "awswaf:managed:aws:core-rule-set:SizeRestrictions_Body"}
        - {uri_path: {starts_with: /web/dataset/}, negate: true}
disable_custom_rules: []
rate_limit: {limit: 2000, window_sec: 300, action: block}   # optional
geo_block: {countries: [KP], action: block}                # optional
path_overrides: [{path_prefix: /web/content/, rules: {RestrictedExtensions_URIPATH: count}}]  # nginx-only
block_page: aws                         # aws | <file name in $WAF_CONFIG_DIR/pages/>
```
`profiles/<name>.yaml`: `version: 1`, `name`, `description`, optional `extends: <profile>`, then WAF-settings keys only.
Condition kinds (exactly one per condition, plus optional `negate: true`):
- `label: <full label>`, `label_namespace: <group label_ns>`;
- `uri_path|header|query_arg: {name (header/query_arg only), exact|starts_with|contains|regex, transform: [urlDecodeUni|lowercase]}`;
- `method: [GET, POST]`;
- `ip_set: [CIDR…]`;
- `geo: [ISO2…]`;
- `size: {component: body|query_string|uri_path|cookie|header:<Name>, op: gt|ge|lt|le|eq, value: <int>}`.

Built-in defaults (lowest layer of the merge): mode enforce, default_action allow, body_limit 8192, client_ip remote_addr, fail closed/open, block_page aws, and `rule_groups` = the three non-optional catalog groups, enabled, with no overrides.

## Sub-phases

### 0.1 Baseline import and repo skeleton
- **Agent:** agent-1
- **Assignment:** implement; self-review after the diff.
- **Files:**
  - READ: `.gitignore`, `README.md`, `scripts/*.sh`.
  - WRITE: `.gitignore`.
  - NEW: `Makefile`, `scripts/lab-env.sh`.
- **Change:**
  - Preconditions: branch `main`, no commits; untracked `.gitignore README.md data/ docs/ scripts/` (pre-existing work owned by this unit).
  - Contract: the first commit contains the pre-existing files unchanged, plus the `.gitignore` additions and the `Makefile`.
  - Scope: do not modify the content of `docs/aws`, `data/` or `scripts/`.
  - Steps:
    1. S1 — Append to `.gitignore`:
       ```
       # build / runtime (never commit)
       /build/
       /.run/
       /wafctl/bin/
       *.pem
       *.key
       /lab/config/state/
       node_modules/
       /tests/legit/test-results/
       ```
       Expected: `git check-ignore -q x.pem` succeeds.
    2. S2 — Create `Makefile` with `SHELL := /bin/bash`, `.PHONY` targets and these recipes:
       - `fetch:` → `./scripts/fetch-all.sh`
       - `wafctl:` → `cd wafctl && go build -o bin/wafctl ./cmd/wafctl`
       - `test-unit:` → `cd wafctl && go test ./...`
       - `help:` → prints the targets

       Later units append targets. Expected: `make help` exits 0.
    3. S3 — Create `scripts/lab-env.sh` (meant to be sourced):
       ```bash
       # source scripts/lab-env.sh  — lab environment for gates and manual runs
       _r="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
       export WAF_HOME="$_r" WAF_CONFIG_DIR="$_r/lab/config" WAF_DATA_DIR="$_r/.run"
       export PATH="$_r/wafctl/bin:/usr/local/go/bin:$HOME/.cargo/bin:$PATH"
       ```
       Expected: `bash -c 'source scripts/lab-env.sh && echo $WAF_DATA_DIR'` prints `<repo>/.run`.
  - Recovery boundary: none.
  - Failure handling: if `git status` shows unexpected files, stop and report to agent-1.
- **Unit tests:** N/A — no code.
- **e2e tests:** N/A.
- **Done:**
  - `git ls-files | wc -l` ≥ 30;
  - `git check-ignore build/x .run/x a.pem | wc -l` = 3 (`-q` accepts one path only);
  - G-U01 passes;
  - closure commit made (it includes the plan folder).

### 0.2 Catalog, pattern data, block pages
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - READ: `docs/plans/001_plan-nginx-aws-waf/snippets/catalog-rules.yaml`, `snippets/data/*`, `vendor/coreruleset/rules/scanners-user-agents.data` (run `./scripts/fetch-crs.sh` if missing).
  - NEW: `waf/catalog/rules.yaml`, `waf/data/{bad-bots.data,ec2-metadata.data,lfi-targets.data}`, `waf/static/{403.html,500.html}`, `waf/README.md`.
- **Change:**
  - Preconditions: 0.1 DONE.
  - Contract: the catalog is byte-identical to the snippet minus line 1. The data files hold one pattern per line, with no comments and no blank lines.
  - Steps:
    1. S1 — `mkdir -p waf/catalog waf/data waf/static`. Run `tail -n +2 <snippet> > waf/catalog/rules.yaml` and `cp snippets/data/*.data waf/data/`. Run `grep -v '^#' vendor/coreruleset/rules/scanners-user-agents.data | grep -v '^[[:space:]]*$' > waf/data/bad-bots.data`. Expected: bad-bots has 79 lines, ec2-metadata 11, lfi-targets 11.
    2. S2 — `waf/static/403.html`, the AWS default block body (exact bytes, CRLF line endings):
       `<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n</body>\r\n</html>\r\n`.
       `500.html` is the same with `500 Internal Server Error`. Write them with `printf`.
    3. S3 — `waf/README.md`: explains the catalog fields (id, name, label, default_action, fidelity exact|approx|stub, detectors = list of chains, each chain a list of `{vars, op, t}` links, ANDed) and the ID scheme from D2/D23.
  - Recovery boundary: none.
  - Failure handling: if the CRS vendor dir is missing and the fetch fails (network), BLOCKED with question to the user.
- **Unit tests:** covered by 0.3 T-CAT1 (catalog parses, counts).
- **e2e tests:** N/A.
- **Done:**
  - `diff <(tail -n +2 snippets/catalog-rules.yaml) waf/catalog/rules.yaml` is empty;
  - line counts as in S1;
  - G-U02 passes.

### 0.3 wafctl skeleton and catalog package
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:** NEW:
  - `wafctl/go.mod`, `wafctl/go.sum`;
  - `wafctl/cmd/wafctl/main.go`;
  - `wafctl/internal/env/env.go`;
  - `wafctl/internal/catalog/{catalog.go,catalog_test.go}`;
  - `wafctl/internal/version/version.go`.
- **Change:**
  - Preconditions: 0.2 DONE.
  - Contract:
    - `env.Home() (string, error)`, `env.ConfigDir() string`, `env.DataDir() string` (D19).
    - `catalog.Load(path string) (*Catalog, error)`. Types:
      ```go
      type Link struct { Vars string `yaml:"vars"`; Op string `yaml:"op"`; T []string `yaml:"t"` }
      type Rule struct { ID int `yaml:"id"`; Name, Label, DefaultAction, Fidelity string; Detectors [][]Link `yaml:"detectors"`; Group *Group `yaml:"-"` }
      type Group struct { Key, Name, Vendor string; WCU int `yaml:"wcu"`; LabelNS string `yaml:"label_ns"`; Optional bool; Rules []*Rule }
      type Catalog struct { Version int; Groups []*Group }
      ```
      (snake_case yaml tags: `default_action`, `label_ns`.)
    - Methods: `RuleByName(group, name)`, `RuleByID(id)`, `RuleByLabel(fullLabel)`, `GroupByName(name)`, `GroupByKey(key)`, `FullLabel(r) = r.Group.LabelNS + r.Label`, `BaseID(g) = g.Rules[0].ID / 10000 * 10000`.
    - Load validation errors:
      - version ≠ 1;
      - duplicate id, name or label;
      - id not a multiple of 10;
      - more than 7 detectors;
      - default_action ∉ {block, count};
      - fidelity ∉ {exact, approx, stub};
      - an empty chain;
      - a link with empty vars or op.
  - Steps:
    1. S1 — `cd wafctl && go mod init nginxawswaf/wafctl && go get gopkg.in/yaml.v3@v3.0.1`. Create `version.Version = "0.1.0-dev"` (overridable with `-ldflags -X`).
    2. S2 — Write the catalog package. Decode with `yaml.NewDecoder(f)` + `dec.KnownFields(true)`. After decoding, set `r.Group`.
    3. S3 — `main.go`: dispatch on `os.Args[1]` through `map[string]func([]string) int`. Implement `version` and `catalog list [--group KEY] [--format table|json]`. The table columns are `ID GROUP NAME DEFAULT FIDELITY DETECTORS`, written with `text/tabwriter`. Implement `catalog show <name|id>`, which prints the YAML of the rule. Unknown command → usage on stderr, exit 2.
  - Failure handling: if `go get` needs a network that is unavailable, BLOCKED.
- **Unit tests:** `catalog_test.go`, loading `../../../waf/catalog/rules.yaml`:
  - T-CAT1: 5 groups; non-optional keys in order `iprep, crs, kbi`; full order `iprep, anonip, crs, kbi, sqli`; 3+2+22+20+8 = 55 rules; `RuleByName("AWSManagedRulesCommonRuleSet","NoUserAgent_HEADER").ID == 1200010`; `FullLabel` of 1300050 == `awswaf:managed:aws:known-bad-inputs:Host_Localhost_Header`; 8 stubs with 0 detectors in kbi.
  - T-CAT2: loading a temp file with a duplicate id fails with an error containing `duplicate id`; an unknown key fails.
  - G-U03.
- **e2e tests:** `./bin/wafctl catalog list | wc -l` = 56 (header + 55).
- **Done:** tests pass; `go vet ./...` is clean; G-U03 passes.

### 0.4 Config types, loading, profile merge
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - NEW: `wafctl/internal/config/{types.go,load.go,merge.go,config_test.go}`, `wafctl/internal/config/testdata/{node.yaml,sites/,profiles/}`, `profiles/{aws-default.yaml,shadow.yaml,strict.yaml}`.
- **Change:**
  - Preconditions: 0.3 DONE.
  - Contract:
    - Types follow "Config schema" above. WAF settings are a struct `WAF` embedded with `yaml:",inline"` into `Site` and `Profile`. Optional scalars use pointers where "unset" must differ from zero (`Enabled *bool`, `RateLimit *RateLimit`, `GeoBlock *GeoBlock`, `ScopeDown *Match`, `TrustedProxies []string`, where nil means unset).
    - `Cond` has fields for every kind; `StrMatch{Exact, StartsWith, Contains, Regex string; Transform []string}`.
    - `config.Load(dir string) (*Config, error)` reads `node.yaml`, `sites/*.yaml` (sorted by file name) and the profiles. Profiles are searched in `<dir>/profiles` first, then `$WAF_HOME/profiles`. `Config{Node, Sites []*Site, Profiles map[string]*Profile}`.
    - `config.Effective(cfg, siteID, cat) (*EffectiveSite, error)` returns the merged settings plus an `Origins map[string]string` (key such as `rule:<Group>/<Rule>` → `default|profile:<name>|site|bypass|path_override`) used by explain.
    - Merge order: built-in defaults ← profile chain, root first (cycle → error `profile cycle a->b->a`) ← site ← bypass (mode=count when active; bypass state is read by 1.5; here a parameter `bypass bool`).
    - Merge rules:
      - scalars: a non-zero value overrides;
      - `rule_groups`: by name; `Enabled` and `OverrideAction` override when set; `RuleActionOverrides` merged key by key; `ScopeDown` overrides when non-nil; unknown names are appended in order;
      - `custom_rules`: concatenated; the same name replaces in place;
      - `disable_custom_rules` removes by name (unknown name → error);
      - `path_overrides`: concatenated;
      - pointers override when non-nil.
  - Steps:
    1. S1 — `types.go` + `load.go`, decoding with `KnownFields(true)`. An error carries the file path: `fmt.Errorf("%s: %w", path, err)`. Check that each site file name equals `site_id + ".yaml"`.
    2. S2 — `merge.go`, implementing `Effective` with the rules above.
    3. S3 — Shipped profiles:
       - `aws-default.yaml`: `name: aws-default`, description, no settings; the defaults equal the one-click ACL.
       - `shadow.yaml`: `extends: aws-default`, `mode: count`.
       - `strict.yaml`: `extends: aws-default`; `rule_groups` enables `AWSManagedRulesSQLiRuleSet` and `AWSManagedRulesAnonymousIpList`.
  - Failure handling: unclear merge semantics → ask agent-1, do not invent.
- **Unit tests:** `config_test.go` with testdata:
  - T-CFG1: a site with no profile → 3 groups enabled; mode enforce; body 8192.
  - T-CFG2: a site with profile shadow → mode count, `Origins["mode"]=="profile:shadow"`.
  - T-CFG3: a profile sets `SizeRestrictions_BODY: count` and the site sets `NoUserAgent_HEADER: count` → both present.
  - T-CFG4: a profile custom rule `A` plus a site rule `A` → one rule, the site version.
  - T-CFG5: profile cycle → error.
  - T-CFG6: an unknown key in the site → error naming the file.
  - T-CFG7: bypass=true → mode count, origin `bypass`.
  - G-U04.
- **e2e tests:** N/A.
- **Done:** tests pass; G-U04 passes.

### 0.5 Validation and AWS-compatibility classification
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - NEW: `wafctl/internal/config/{validate.go,compat.go,validate_test.go}`, `lab/config/node.yaml`, `lab/config/sites/demo.yaml`.
  - WRITE: `wafctl/cmd/wafctl/main.go` (add `validate`).
- **Change:**
  - Preconditions: 0.4 DONE.
  - Contract:
    - `Validate(cfg, cat) []Issue` with `Issue{File, Path, Msg string; Severity "error"|"warning"}`.
    - `Compat(eff, cat) []string`: reasons the site is nginx-only; empty means aws-compatible.
    - `wafctl validate [--config DIR]` prints `file: path: msg` lines, then per site `site <id>: aws-compatible` or `site <id>: nginx-only (<reasons joined by "; ">)`. Exit 2 when any error exists.
  - Validation rules (errors unless marked warning):
    1. node: node_id regex; role and network enums; listen ports 1–65535; workers ≥ 0; `audit.scope` ∈ {all, relevant}.
    2. site_id regex, unique; server_names non-empty, unique across sites, matching `^[a-z0-9*.-]+$`; app enum; upstream.servers non-empty `host:port`; `tls.mode` enum; when tls ≠ off the cert/key files exist under `$WAF_DATA_DIR/certs/<site>/` (warning if WAF_DATA_DIR is missing — lab render).
    3. mode, default_action, `fail.*` enums; `body_limit` 1..1048576.
    4. `client_ip.source` enum; `xff` requires non-empty `trusted_proxies`; each one is a valid CIDR; `0.0.0.0/0` or `::/0` is allowed only with `node.lab.enabled`.
    5. Rule groups:
       - names exist in the catalog;
       - `override_action` ∈ {none, count};
       - override keys are rule names of that group;
       - values ∈ {block, count, allow};
       - an optional group is active only with `enabled: true`.
    6. Custom rules:
       - unique names `^[A-Za-z0-9_-]{1,128}$`, at most 99 per site;
       - slot is `start` or `after:<enabled group name>`;
       - action enum; `match.all` non-empty;
       - each condition has exactly one kind;
       - `label` exists in the catalog (`RuleByLabel`); `label_namespace` equals some group `label_ns`;
       - a regex that fails Go `regexp.Compile` → warning (PCRE ≠ RE2);
       - method values uppercase `[A-Z]+`;
       - `ip_set` CIDRs parse;
       - `geo` codes `^[A-Z]{2}$`, and `node.geoip.enabled` is required;
       - `size.component` matches `^(body|query_string|uri_path|cookie|header:[A-Za-z0-9-]+)$`, op enum, value ≥ 0;
       - `transform` ∈ {urlDecodeUni, lowercase}.
    7. `rate_limit`: limit ≥ 10, window_sec ∈ {60, 120, 300, 600}, action ∈ {block, count}. `geo_block`: as `geo` above.
    8. `path_overrides`: path_prefix starts with `/`; rule names exist; actions enum.
    9. At most 100 sites.
  - Compat reasons:
    - `body_limit not in {8192,16384,32768,49152,65536}`;
    - `client_ip.source=xff`;
    - `fail.pcre_limit=block` or `fail.body_error=closed|block` (AWS has fail open/closed only for unreachable WAF; we map closed→aws default and open→the ALB fail-open option);
    - `path_overrides`;
    - `audit.scope=relevant` (node level, reported for every site);
    - `block_page` other than aws (AWS custom responses are possible, but not exported in v1).
  - Steps:
    1. S1 — `validate.go` + `compat.go` as above.
    2. S2 — `validate` command.
    3. S3 — Lab example config:
       - `lab/config/node.yaml`: role all-in-one, network bridge, lab.enabled true, node_id `lab-node-1`.
       - `sites/demo.yaml`: site_id demo, server_names `[demo.lab.test]`, app generic, upstream `["echo:8081"]`, client_ip xff with `trusted_proxies [0.0.0.0/0, "::/0"]`.
- **Unit tests:** `validate_test.go`, one table-driven case per numbered rule (≥ 1 invalid fixture each, ≥ 14 cases; each asserts a substring of the message) (T-VAL1..). T-CMP1: demo site → reasons contain `client_ip.source=xff`; an aws-default site with remote_addr → no reasons. G-U05.
- **e2e tests:** `WAF_DATA_DIR=$PWD/.run ./wafctl/bin/wafctl validate --config lab/config` → exit 0; prints `site demo: nginx-only (client_ip.source=xff)`.
- **Done:** tests pass; G-U05 passes.

## Phase gates and closure
- Required gates: G-U01..G-U05, then G-P0 (`make wafctl test-unit` + `wafctl validate --config lab/config`).
- README obligation: 0.1 leaves README untouched; README is rewritten in 1.9. Evidence: README sections still accurate (resources table).
- Every sub-phase DONE or SKIPPED with a reason. Run the full phase gates now.
- agent-1 reviews integration, invariants, tests and documentation.
- Open closure unit P0, record the actual review and verified phase result, mark the phase DONE and close it. Commit with subject `phase(001/P0): PHASE 0 COMPLETE — Foundations; gates and review passed`.
- P0 edits no production code or tests. A blocked gate keeps P0 OPEN/BLOCKED. A failing gate or rejected review closes that attempt as failed (commit none) and reopens the responsible sub-phase with a new attempt.
