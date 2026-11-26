# Phase 6 — AWS export, optional groups (rate/geo/SQLi/AnonymousIp) e2e, list updates, final acceptance

Intent:
- The optional features are proven end to end.
- `wafctl export-aws` produces a valid CreateWebACL JSON (checked offline with the AWS CLI) and Terraform that passes `terraform validate`.
- IP lists and GeoLite2 update safely on a schedule.
- The G-FINAL reference scenario passes via `make final-check`.

Prerequisites: P1, P3 DONE. P4 and P5 are needed for G-FINAL steps 3 and 7.
Phase closure: P6; review by agent-1.

## State and ownership contract
Read STATE.md §1 first (and PROTOCOL.md once without this skill) for scope, ownership, recovery, checks and commit rules. Open a unit before editing; checkpoint at a recovery boundary; close with evidence. Missing design goes to agent-1, the supervisor. Executor power: low. Follow the steps literally. The export mapping tables below are normative.

## Local design context
Plan revision: rev 1.
- **D14:** rate limit. **D15:** geo. **D28:** export.
- **R11:** offline validation. Exit 255 + `Could not connect` = valid; exit 252 = invalid. Always pass `--cli-binary-format raw-in-base64-out`, because `SearchString` is a blob and we emit raw strings, as the console JSON editor does.
- **R5 addendum:** an ALB body limit goes to `manual_steps`.

### Export model (`wafctl export-aws --site S [--format json|terraform] [--allow-lossy] [--region eu-central-1] [--account 000000000000] [--acl-only] -o FILE`)
1. Compute `Effective(site)` and `Compat()`.
   - With reasons and no `--allow-lossy` → exit 2, listing the reasons.
   - With `--allow-lossy` → the reasons go to `lossy` and the features are omitted.
2. Rule order and priorities. `p` starts at 0 and increments by 10:
   1. rate rule (if any);
   2. custom rules with slot `start` (GeoBlock first);
   3. for each active managed group in catalog order: the group, then its `after:` custom rules.
3. JSON document: `{"web_acl": <CreateWebACL input>, "ip_sets": [<CreateIPSet input>…], "manual_steps": [..], "lossy": [..]}`. `--acl-only` writes only `web_acl`.

**CreateWebACL fields:**
- `Name` = `waf-<site_id>`; `Scope` = `REGIONAL`.
- `DefaultAction` `{"Allow":{}}` or `{"Block":{}}`.
- `VisibilityConfig {SampledRequestsEnabled: true, CloudWatchMetricsEnabled: true, MetricName: "waf-<site_id>"}`.
- `Rules[]`.
- Each rule: `Name`, `Priority`, `VisibilityConfig` (MetricName = Name with `[^A-Za-z0-9_-]` replaced by `_`, cut at 128 characters), plus `Statement`, and either `Action` (custom/rate) or `OverrideAction` (managed).

**Managed group rule:**
```json
{"Name": "AWS-<GroupName>", "Priority": p, "OverrideAction": {"None": {}} | {"Count": {}},
 "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "<GroupName>",
   "RuleActionOverrides": [{"Name": "<Rule>", "ActionToUse": {"Count": {}} | {"Block": {}} | {"Allow": {}}}],   // only rules whose effective action != catalog default; omit key if empty
   "ScopeDownStatement": <stmt>}}}                                                                    // omit if no scope_down
```
Site `mode: count` exports every group with OverrideAction Count and every custom/rate action as Count. If `default_action` is `block` as well, that is a lossy reason: `shadow mode with default_action block`.

**Condition → statement (single condition = the statement itself; several = `{"AndStatement": {"Statements": [...]}}`; negate = `{"NotStatement": {"Statement": s}}`):**

| Condition | Statement |
|---|---|
| label L | `{"LabelMatchStatement": {"Scope": "LABEL", "Key": L}}` |
| label_namespace N | `{"LabelMatchStatement": {"Scope": "NAMESPACE", "Key": N}}` |
| uri_path exact/starts_with/contains | `{"ByteMatchStatement": {"SearchString": v, "FieldToMatch": {"UriPath": {}}, "TextTransformations": T, "PositionalConstraint": "EXACTLY"/"STARTS_WITH"/"CONTAINS"}}` |
| uri_path regex | `{"RegexMatchStatement": {"RegexString": v, "FieldToMatch": {"UriPath": {}}, "TextTransformations": T}}` |
| header{name} | as uri_path, with `{"SingleHeader": {"Name": lower(name)}}` |
| query_arg{name} | as uri_path, with `{"SingleQueryArgument": {"Name": name}}` |
| method [M] | one `ByteMatchStatement` per M (`{"Method": {}}`, EXACTLY); more than one → `{"OrStatement": {"Statements": [...]}}` |
| ip_set [cidrs] | `{"IPSetReferenceStatement": {"ARN": "<arn of waf-<site>-<rule>-v4>"}}`; if both v4 and v6 exist, an OrStatement of two |
| geo [CC] | `{"GeoMatchStatement": {"CountryCodes": [...]}}` |
| size | `{"SizeConstraintStatement": {"FieldToMatch": F, "ComparisonOperator": "GT"/"GE"/"LT"/"LE"/"EQ", "Size": v, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}`; F: body→`{"Body": {"OversizeHandling": "CONTINUE"}}`, query_string→`{"QueryString": {}}`, uri_path→`{"UriPath": {}}`, cookie→`{"Cookies": {"MatchPattern": {"All": {}}, "MatchScope": "ALL", "OversizeHandling": "CONTINUE"}}`, header:X→`{"SingleHeader": {"Name": lower(X)}}` |

- `T` = the transforms mapped urlDecodeUni→`URL_DECODE_UNI` and lowercase→`LOWERCASE`, with priorities 0..n. An empty list → `[{"Priority": 0, "Type": "NONE"}]`.
- IP set: `{"Name": "waf-<site>-<rule>-v4", "Scope": "REGIONAL", "IPAddressVersion": "IPV4", "Addresses": [...]}`. The ARN is `arn:aws:wafv2:<region>:<account>:regional/ipset/<name>/00000000-0000-0000-0000-000000000000`. manual_steps gets "replace IP set ARNs after CreateIPSet" (JSON format only).
- Custom rule action: `{"Block": {}}` / `{"Allow": {}}` / `{"Count": {}}`.
- Rate rule: `{"Name": "RateLimit", "Action": {"Block": {}} | {"Count": {}}, "Statement": {"RateBasedStatement": {"Limit": limit, "EvaluationWindowSec": window_sec, "AggregateKeyType": "IP"}}}`.

**manual_steps entries:**
- body_limit ≠ 8192 (in the AWS set) → `"Set the ALB WAF body inspection limit to <N/1024> KB (Load balancer attributes / WAF integration)"`;
- `fail.*` at the defaults → nothing; fail-open is never auto-mapped (it is listed as lossy by Compat when nginx-only);
- always → `"Associate the web ACL with the ALB (aws_wafv2_web_acl_association or console)"`.

**Terraform format:**
- A generic converter walks the same JSON `web_acl` object:
  - object member `K: {...}` → block `snake(K) { … }`;
  - empty object → `snake(K) {}`;
  - array of objects → repeated blocks named `singular(snake(K))`;
  - array of scalars → attribute list;
  - scalar → attribute.
- `snake`: `CamelCase` → `camel_case`, with the special cases `IPSetReferenceStatement`→`ip_set_reference_statement`, `IPAddressVersion`→`ip_address_version`, `ARN`→`arn`, `URL_DECODE_UNI` (values unchanged).
- `singular`: `rules`→`rule`, `rule_action_overrides`→`rule_action_override`, `text_transformations`→`text_transformation`, `statements`→`statement`, `country_codes` stays an attribute (scalars).
- Special cases:
  - `Statements` inside And/Or/Not become `statement {}` blocks;
  - `NotStatement.Statement` becomes `statement {}`;
  - `ManagedRuleGroupStatement.ScopeDownStatement` becomes `scope_down_statement {}`;
  - the IP set ARN becomes the expression `aws_wafv2_ip_set.<tfname>.arn` (unquoted);
  - `Name`/`Scope`/`DefaultAction`/`VisibilityConfig`/`Rules` sit at the resource level: `resource "aws_wafv2_web_acl" "<site_tf>" { name = …; scope = "REGIONAL"; default_action { allow {} } … }`.
- Extra resources:
  - `aws_wafv2_ip_set` per IP set;
  - `variable "alb_arn" { type = string, default = "" }`;
  - `resource "aws_wafv2_web_acl_association" "this" { count = var.alb_arn == "" ? 0 : 1; resource_arn = var.alb_arn; web_acl_arn = aws_wafv2_web_acl.<site_tf>.arn }`;
  - `terraform { required_providers { aws = { source = "hashicorp/aws", version = "~> 6.0" } } }`;
  - `provider "aws" { region = "<region>" }`.
- `manual_steps` and `lossy` are written as `#` comments at the top.
- Values: strings are quoted with `strconv.Quote`-compatible escaping. `${` is escaped to `$${`, and `%{` to `%%{`.
- Converter failure policy: if `terraform validate` rejects a block name, fix the mapping table (in code and here as a plan-correction note in §6). Never hand-edit the output.

### List updates
- `scripts/fetch-ip-lists.sh` gains `OUT="${OUT:-$ROOT/data/ip-reputation}"`, which is backward compatible.
- `wafctl lists update [--force]`:
  1. Runs the script with `OUT=<tmpdir>`.
  2. For each list file, refuses the replacement when the new non-comment line count is < 50 % of the current one (download failure guard, because the script writes an empty file on failure), unless `--force`.
  3. Validates each line as an IP/CIDR (`net/netip`).
  4. Copies the files to `$WAF_DATA_DIR/lists/` via tmp + rename.
  5. Keeps `custom-reputation.txt` untouched.
  6. If anything changed, runs `wafctl apply` (a reload re-reads `@ipMatchFromFile`).
  7. Prints a table `LIST OLD NEW STATUS`.
- systemd units:
  - `wafctl-lists.timer`: `OnCalendar=*-*-* 04:17:00`, `RandomizedDelaySec=30m`;
  - `wafctl-geoip.timer`: weekly. Its service runs `docker run --rm --env-file $WAF_CONFIG_DIR/secrets.env -e GEOIPUPDATE_EDITION_IDS="GeoLite2-Country GeoLite2-ASN" -v $WAF_DATA_DIR/geoip:/usr/share/GeoIP maxmindinc/geoipupdate:v8.0.0`, then `wafctl apply`. The account and key go into `secrets.env` as `GEOIPUPDATE_ACCOUNT_ID` / `GEOIPUPDATE_LICENSE_KEY`, written by the user.

## Sub-phases

### 6.1 Optional features end to end (SQLi, AnonymousIp, rate limit, geo)
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - NEW: `lab/config/sites/{ratelimit,ratecount,geo}.yaml`, `tests/corpus/optional.yaml`, `tests/e2e/ratelimit.sh`.
  - WRITE: `lab/config/node.yaml` (`geoip.enabled: true`), `Makefile` (`lab-min-up` depends on `geoip-test`).
- **Change:**
  - Preconditions: P1 and P3 DONE.
  - Contract (all demo-like generic sites on echo with xff):
    - `ratelimit`: `rate_limit {limit: 10, window_sec: 60, action: block}`;
    - `ratecount`: the same with `action: count`;
    - `geo`: `geo_block {countries: [GB], action: block}`.
    - `optional.yaml`:
      - `geo-gb` (xff 2.125.160.216 → 403 GeoBlock);
      - `geo-se` (xff 89.160.20.112 → 200 Default_Action);
      - `geo-v6-jp` (xff 2001:218::1 → 200);
      - strict-site cases are already in sqli/anonip.
    - `ratelimit.sh`:
      - send 40 requests in a quick loop from xff 198.51.100.77 to `ratelimit` → at least one 403. The access-log `rl` for those requests is `REJECTED`, and their events have `terminating_type=RATE_BASED` and `action=BLOCK`;
      - on `ratecount`, all 200, with `rl=REJECTED_DRY_RUN` on at least one request.
  - Steps:
    1. S1 — Sites + corpus.
    2. S2 — The script.
    3. S3 — Run `make test-e2e` and the script.
  - Failure handling: geo lookups returning empty → check that the mmdb is mounted at `/etc/waf/geoip/GeoLite2-Country.mmdb` and that render emitted `SecGeoLookupDb`.
- **Unit tests:** T-R13: the render of `geo` contains `SecGeoLookupDb` and the GeoBlock custom rule at slot start. T-R14: `ratelimit` renders `limit_req_zone … rate=10r/m` and `burst=10`. G-U61.
- **e2e tests:** `make test-e2e` (with optional.yaml) passes; `tests/e2e/ratelimit.sh` passes. G-U61.
- **Done:** G-U61 passes.

### 6.2 `export-aws` JSON
- **Agent:** agent-1
- **Assignment:** implement; self-review against the mapping tables.
- **Files:**
  - NEW: `wafctl/internal/awsexport/{model.go,json.go,stmt.go,awsexport_test.go}`, `wafctl/internal/awsexport/testdata/golden/*.json`, `scripts/aws-validate-acl.sh`.
  - WRITE: `cmd/wafctl/main.go`.
- **Change:**
  - Preconditions: 6.1 DONE.
  - Contract: as in the Export model. Build the model with Go `map[string]any`, or with structs carrying `json` tags and `omitempty`, so that empty RuleActionOverrides and ScopeDown are omitted.
  - `scripts/aws-validate-acl.sh FILE`:
    ```
    out=$(env -u AWS_PROFILE AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x AWS_CONFIG_FILE=/dev/null \
      aws wafv2 create-web-acl --cli-input-json "file://$1" --cli-binary-format raw-in-base64-out \
      --endpoint-url http://127.0.0.1:9 --region eu-central-1 2>&1); rc=$?
    [ $rc -eq 255 ] && grep -q 'Could not connect' <<<"$out" && { echo VALID; exit 0; }
    echo "$out"; exit 1
    ```
    Same for IP sets with `create-ip-set`. If `aws` is missing, use `docker run --rm -v …:/w amazon/aws-cli:<pin>` (pin the tag found via `docker pull amazon/aws-cli:latest && docker run --rm amazon/aws-cli --version`, recorded in §6).
  - Steps:
    1. S1 — Statements (`stmt.go`).
    2. S2 — The rules/priorities model.
    3. S3 — The command.
    4. S4 — The validate script.
- **Unit tests:**
  - T-EXP1: golden for a profile-only site (aws-default, remote_addr fixture) → 3 managed rules, priorities 0/10/20, no overrides.
  - T-EXP2: golden for a fixture equal to `tuned` without xff/path_overrides → override + scope-down Not(ByteMatch STARTS_WITH) + custom And(Label, Not(Regex…)) after CRS, priority between CRS and KBI.
  - T-EXP3: nginx-only site without `--allow-lossy` → error listing the reasons.
  - T-EXP4: method with two values → OrStatement.
  - T-EXP5: shadow mode → all Count.
  - T-EXP6: the rate rule comes first.
  - G-U62.
- **e2e tests:**
  - For every lab site: `wafctl export-aws --site <s> --allow-lossy --acl-only -o build/aws/<s>.json && scripts/aws-validate-acl.sh build/aws/<s>.json` → VALID (T-EXP7).
  - shop18's lossy list equals `["client_ip.source=xff"]` (lab artefact).
  - G-U62.
- **Done:** G-U62 passes.

### 6.3 `export-aws` Terraform
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:** NEW: `wafctl/internal/awsexport/{hcl.go,hcl_test.go}`, `testdata/golden/*.tf`, `scripts/tf-validate-export.sh`. WRITE: `cmd/wafctl/main.go`.
- **Change:**
  - Preconditions: 6.2 DONE.
  - Contract: as in "Terraform format". `scripts/tf-validate-export.sh FILE.tf` copies the file into a temp dir and runs the pinned terraform image (from 5.5): `init -backend=false` then `validate`. It prints `VALID` on `Success!`.
  - Steps:
    1. S1 — The converter.
    2. S2 — The name tables.
    3. S3 — The script.
- **Unit tests:** T-TF1: golden HCL for the T-EXP2 fixture; T-TF2: escaping of `${` in a SearchString; T-TF3: the IP set reference is an unquoted expression. G-U63.
- **e2e tests:** `wafctl export-aws --site shop18 --format terraform --allow-lossy -o build/aws/shop18.tf && scripts/tf-validate-export.sh build/aws/shop18.tf` → VALID. The same for `tuned` (fixture with ip_set: add a custom rule with `ip_set` to the `allowlist` lab site, slot start, allow, `[203.0.113.200/32, "2001:db8::1/128"]`). G-U63.
- **Done:** G-U63 passes.

### 6.4 List and GeoIP updates
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - NEW: `wafctl/internal/lists/{update.go,update_test.go}`, `deploy/systemd/{wafctl-lists.service,wafctl-lists.timer,wafctl-geoip.service,wafctl-geoip.timer}`.
  - WRITE: `scripts/fetch-ip-lists.sh` (OUT env only), `cmd/wafctl/main.go`, `docs/operations.md`.
- **Change:**
  - Preconditions: 6.3 DONE.
  - Contract: as in "List updates".
  - Steps:
    1. S1 — The script change (a one-line diff).
    2. S2 — The update logic.
    3. S3 — The systemd units.
    4. S4 — Docs.
- **Unit tests:**
  - T-LST1: the 50 % guard refuses (fixture old 100 lines, new 10) and `--force` accepts;
  - T-LST2: an invalid CIDR line → error naming file:line;
  - T-LST3: custom-reputation is untouched.
  - G-U64.
- **e2e tests:** `wafctl lists update` on the lab (network) → table printed, apply ran, and corpus `iprep-*` cases still pass. Offline → the guard keeps the old lists (exit 0 with status `kept`). G-U64.
- **Done:** G-U64 passes.

### 6.5 Final acceptance, AWS docs, release notes
- **Agent:** agent-1
- **Assignment:** implement; self-review; then the plan-level review in PLAN closure.
- **Files:** NEW: `scripts/final-check.sh`, `docs/aws-export.md`, `CHANGELOG.md`. WRITE: `Makefile` (`final-check`), `README.md`, `docs/performance.md` (re-run).
- **Change:**
  - Preconditions: 6.4 DONE; P2–P5 DONE.
  - Contract: `scripts/final-check.sh` runs G-FINAL steps 1–8 from the overview, in order, fails fast and prints `G-FINAL step N OK`:
    1. `make lab-up` then `wafctl test run --suite tests/corpus`;
    2. `make lab-legit`;
    3. the events count in ClickHouse within 10 s for the step-1 run id, plus `wafctl stats --since 15m --format json` non-empty, plus `scripts/check-dashboards.sh`;
    4. `wafctl report --html --since 1h -o build/final-report.html` (no external refs);
    5. `wafctl logs export --since 1h --format aws -o build/final-aws.jsonl`, where every line has `httpRequest.requestId`;
    6. `wafctl bypass shop18 --ttl 10m --reason final-check`; an attack on shop18 → 200, and its event has `shadow_action=BLOCK`; then `bypass clear shop18`;
    7. `tests/e2e/alerts.sh` step 3 (block spike reaches alert-sink);
    8. export-aws shop18 terraform `--allow-lossy` + `tf-validate-export.sh`.

    **`docs/aws-export.md` (Italian):** the mapping table, the lossy features, manual steps, validation commands, and how to apply with Terraform (user-run, not automated).

    **`CHANGELOG.md`:** 0.1.0, listing features per phase.
  - Steps:
    1. S1 — The script.
    2. S2 — Docs.
    3. S3 — `scripts/bench.sh` re-run (G-PERF) with the full stack running.
    4. S4 — `make final-check`.
- **Unit tests:** N/A — acceptance script.
- **e2e tests:** G-FINAL, G-PERF. G-U65.
- **Done:** G-U65 passes.

## Phase gates and closure
- Required gates: G-U61..G-U65, then G-P6 (`make test-unit && make final-check`).
- README obligation: unit 6.5 (final README, aws-export docs, CHANGELOG).
- Every sub-phase DONE or SKIPPED with a reason. Run the full phase gates now.
- agent-1 reviews the export fidelity versus the mapping tables, lossy reporting, the list-update safety and the docs.
- Open P6, record the review, mark DONE. Commit `phase(001/P6): PHASE 6 COMPLETE — AWS export, optional groups, final acceptance; gates and review passed`.
- Then PLAN closure per STATE §1.
