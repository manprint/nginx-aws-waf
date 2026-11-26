# Phase 2 — Lab: Odoo 12/14/16/18, legit flows, attack generators, matrix, Odoo profiles

Intent: `make lab-up` runs four Odoo sites (shop12/14/16/18) behind the WAF node. Playwright legit flows pass with 0 WAF blocks under profiles `odoo-12|14|16|18`. Every corpus attack retargeted to the Odoo sites is blocked, or listed in an explicit, justified exception file. A matrix report (clickhouse-local over the raw JSONL) documents the rule × site results against the AWS-default outcome.
Prerequisites: P1 DONE.
Phase closure: P2; review by agent-1.

## State and ownership contract
Read STATE.md §1 first (and PROTOCOL.md once without this skill) for scope, ownership, recovery, checks and commit rules. Open a unit before editing; checkpoint at a recovery boundary; close with evidence. Missing design goes to agent-1, the supervisor. Executor power: low. Follow the steps literally. Profile tuning in 2.5 follows the fixed algorithm given there; never weaken a rule beyond it.

## Local design context
Plan revision: rev 1.
- **D27 (Odoo profiles):** aws-compatible only. Allowed forms are rule → count plus a label rule that blocks outside allowed path prefixes. No nginx-only feature in an `odoo-*` profile, which T-PRF1 checks with `Compat()` = empty.
- **R9:** Odoo CLI flags.
- **R4:** image tags.
- **D17:** the matrix uses raw JSONL and `clickhouse local`. No ClickHouse server is needed in this phase.

### Lab topology (`deploy/compose/lab.yml`, project `waf`, network `waf_lab`, used with node.yml + node.bridge.yml)
| Service | Image | Command / args | Notes |
|---|---|---|---|
| `pg12` | `postgres:12` | env `POSTGRES_USER=odoo POSTGRES_PASSWORD=odoo POSTGRES_DB=postgres` | volume `pg12:/var/lib/postgresql/data` |
| `pg13` | `postgres:13` | same | volume `pg13` |
| `pg15` | `postgres:15` | same | volume `pg15` |
| `pg16` | `postgres:16` | same | volume `pg16` |
| `odoo12` | `odoo:12` | `odoo --db_host=pg12 --db_user=odoo --db_password=odoo --proxy-mode --db-filter=^lab$ --workers=2 --longpolling-port=8072 --max-cron-threads=1 --limit-time-real=600` | volume `odoo12:/var/lib/odoo` |
| `odoo14` | `odoo:14` | same with pg13 and `--longpolling-port=8072` | |
| `odoo16` | `odoo:16` | same with pg15 and `--gevent-port=8072` | |
| `odoo18` | `odoo:18` | same with pg16 and `--gevent-port=8072` | |
| `echo` | (from lab-min.yml, also included) | | |

Each Odoo service has `depends_on: [pgNN]`, `restart: unless-stopped` and `mem_limit: 1500m`. Ports are not published; traffic goes only through the WAF.

Lab sites (`lab/config/sites/shopNN.yaml`):
- `site_id: shopNN`, `server_names: [shopNN.lab.test]`, `app: odoo`, `profile: odoo-NN`;
- `upstream: {servers: ["odooNN:8069"], realtime: {path: <RT>, servers: ["odooNN:8072"]}, max_body_size: 100m, read_timeout_sec: 720}`;
- `client_ip` xff with trusted `0.0.0.0/0`, `::/0`;
- RT = `/longpolling` for 12 and 14, `/websocket` for 16 and 18.

DB init: `docker compose … run --rm --no-deps odooNN odoo --db_host=pgNN --db_user=odoo --db_password=odoo -d lab -i contacts,crm,sale_management,website_sale,website_crm --without-demo=all --stop-after-init`. Then set the admin password via `--load-language` is not needed; the default user is `admin` with password `admin` in every version.

`/etc/hosts` is not needed. All clients set the Host header (Playwright via `baseURL http://127.0.0.1:8080` plus `extraHTTPHeaders: {Host: …}` is NOT reliable, because Chromium drops a custom Host header). Playwright therefore runs inside the `waf_lab` network as a container and uses `--host-resolver-rules="MAP shopNN.lab.test waf:8080"` to reach the WAF. The `waf` service gets network alias `waf` in node.bridge.yml.

### Odoo profile design (initial; refined in 2.5)
`profiles/odoo-common.yaml`:
```yaml
version: 1
name: odoo-common
description: "Odoo Community: RPC bodies and editor HTML counted, then blocked outside Odoo RPC/editor paths (aws-compatible)"
extends: aws-default
rule_groups:
  - name: AWSManagedRulesCommonRuleSet
    rule_action_overrides:
      SizeRestrictions_BODY: count
      CrossSiteScripting_BODY: count
      GenericRFI_BODY: count
custom_rules:
  - name: OdooBodySizeOutsideRpc
    slot: after:AWSManagedRulesCommonRuleSet
    action: block
    match: {all: [{label: "awswaf:managed:aws:core-rule-set:SizeRestrictions_Body"},
                  {uri_path: {regex: "^/(web/dataset/|web/binary/|mail/|html_editor/|web_editor/|website/|web/action/|longpolling/|websocket|bus/|web/webclient/)"}, negate: true}]}
  - name: OdooXssBodyOutsideEditor
    slot: after:AWSManagedRulesCommonRuleSet
    action: block
    match: {all: [{label: "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"},
                  {uri_path: {regex: "^/(web/dataset/|mail/|html_editor/|web_editor/|website/)"}, negate: true}]}
  - name: OdooRfiBodyOutsideRpc
    slot: after:AWSManagedRulesCommonRuleSet
    action: block
    match: {all: [{label: "awswaf:managed:aws:core-rule-set:GenericRFI_Body"},
                  {uri_path: {regex: "^/(web/dataset/|mail/|html_editor/|web_editor/|website/)"}, negate: true}]}
```
Check every label string against `wafctl catalog list` before writing it. Validation (0.5 rule 6) already rejects unknown labels.

`profiles/odoo-{12,14,16,18}.yaml` contain `extends: odoo-common`, a name and a description listing the version's specific paths (realtime path, upload endpoint). They start with no extra settings; 2.5 adds version-specific entries only when the data requires them.

## Sub-phases

### 2.1 Odoo lab stack
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - NEW: `deploy/compose/lab.yml`, `lab/config/sites/shop{12,14,16,18}.yaml`, `profiles/odoo-{common,12,14,16,18}.yaml`, `scripts/lab-init-odoo.sh`, `tests/e2e/lab-smoke.sh`.
  - WRITE: `deploy/compose/node.bridge.yml` (alias), `Makefile` (`lab-up`, `lab-down`, `lab-reset`).
- **Change:**
  - Preconditions: P1 DONE; free RAM ≥ 10 GB (`free -g`).
  - Contract: the topology above.
  - `lab-init-odoo.sh [12 14 16 18]`:
    1. For each version, skip it if `docker compose … exec -T pgNN psql -U odoo -lqt | cut -d'|' -f1 | grep -qw lab` succeeds. Otherwise run the DB init command.
    2. Then run `docker compose … up -d odooNN`.
    3. Poll `curl -s -o /dev/null -w '%{http_code}' -H 'Host: shopNN.lab.test' http://127.0.0.1:8080/web/login` until 200 (timeout 300 s).
  - Makefile:
    - `lab-up: lab-min-up` sets `WAF_COMPOSE_EXTRA=deploy/compose/lab-min.yml:deploy/compose/lab.yml`, runs `docker compose … up -d pg12 pg13 pg15 pg16`, then `./scripts/lab-init-odoo.sh`, then `wafctl apply`.
    - `lab-down` runs `docker compose … down`.
    - `lab-reset` runs `docker compose … down -v` and asks for confirmation via `read -p` unless `FORCE=1`.
  - Steps:
    1. S1 — Write the files.
    2. S2 — Run `make lab-up` and record the init duration in §6 (recovery boundary after each DB init).
  - Failure handling:
    - an Odoo DB init failure → `docker compose logs odooNN`; module names differ per version → BLOCKED to agent-1 with the log (do not drop modules silently);
    - OOM → lower `--workers` to 1 for that version and record it.
- **Unit tests:** T-PRF1, in `wafctl/internal/config/profiles_test.go` (new): every shipped `profiles/odoo-*.yaml` loads, validates against the catalog and has empty `Compat()`. G-U21.
- **e2e tests:** `tests/e2e/lab-smoke.sh`. For each NN:
  - `GET /web/login` = 200, with `Server` not equal to awselb;
  - `GET /web/login` with `-A ''` = 403;
  - the realtime path returns any non-403 code (`/longpolling/poll` POST `{}` or `/websocket` GET).
  - G-U21.
- **Done:** G-U21 passes.

### 2.2 Corpus retargeting and exception list
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - WRITE: `wafctl/internal/testrun/{corpus.go,run.go}`, `cmd/wafctl/main.go`.
  - NEW: `tests/odoo-exceptions.yaml`, `wafctl/internal/testrun/retarget_test.go`.
- **Change:**
  - Preconditions: 2.1 DONE.
  - Contract:
    - New flags on `wafctl test run`: `--retarget FROM=TO[,FROM=TO]` (replace the case site) and `--exceptions FILE`.
    - Exceptions file:
      ```yaml
      version: 1
      exceptions:
        - case: crs-size-body           # corpus case id
          sites: [shop12, shop14, shop16, shop18]
          expect: {status: 200, terminating_rule: Default_Action}   # replaces the case expectation
          reason: "Odoo RPC bodies > 8 KB on /web/dataset/ are counted (odoo-common)"
      ```
    - A retargeted case without an exception keeps its original expectation. An exception without a `reason` is a load error. Retargeting skips cases that use special sites (`tuned`, `allowlist`, `strict`, `shadow`): only `demo` cases are retargeted.
    - New Makefile target `test-odoo` runs, for each NN, `wafctl test run --suite tests/corpus --filter-site demo --retarget demo=shopNN --exceptions tests/odoo-exceptions.yaml`. `--filter-site` is a new flag that keeps only the cases of that site.
  - Steps:
    1. S1 — Flags and logic.
    2. S2 — Write the initial `tests/odoo-exceptions.yaml`. It holds exactly the cases whose path is not an Odoo RPC path but which odoo-common counts:
       - none expected initially, because the label rules re-block outside RPC paths;
       - keep the file with an empty `exceptions: []`.
    3. S3 — `make test-odoo`.
  - Failure handling: a failing case must be investigated with `wafctl test request` and `wafctl explain shopNN`:
    - a profile bug (a wrong label) → fix the profile;
    - an intended Odoo exception → add it with a reason, and record it in self-review.
- **Unit tests:** T-T4 retarget + exception override; T-T5 an exception without a reason → error. G-U22.
- **e2e tests:** `make test-odoo` passes for 4 sites. G-U22.
- **Done:** G-U22 passes.

### 2.3 Playwright legit flows
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:** NEW:
  - `tests/legit/package.json`, `tests/legit/playwright.config.ts`;
  - `tests/legit/helpers.ts`;
  - `tests/legit/specs/{backend,website,rpc}.spec.ts`;
  - `tests/legit/run.sh`, `tests/legit/README.md`;
  - `deploy/compose/lab-tools.yml` (service `playwright`, profile `tools`).

  WRITE: `Makefile` (`lab-legit`).
- **Change:**
  - Preconditions: 2.2 DONE.
  - Contract:
    - The `playwright` service:
      - image `mcr.microsoft.com/playwright:v1.65.1-noble`;
      - working_dir `/work`, volume `../../tests/legit:/work`, network `waf_lab`;
      - env `SITES` (comma list), `RUN_ID`;
      - command `bash -lc "npm ci && npx playwright test"`.
    - `package.json`: devDependency `@playwright/test` `1.65.1` exactly, with `package-lock.json` committed. Generate it with `docker run --rm -v $PWD/tests/legit:/work -w /work mcr.microsoft.com/playwright:v1.65.1-noble npm install`.
    - `playwright.config.ts`:
      - one `project` per site from env SITES, with `use.baseURL = http://shopNN.lab.test`;
      - `launchOptions.args: ['--host-resolver-rules=MAP *.lab.test waf:8080']`;
      - `extraHTTPHeaders: {'X-Waf-Test': `${RUN_ID}-legit`}`;
      - workers 4, retries 0, reporter `list` + `json` (`test-results/results.json`).
    - `helpers.ts`:
      - a `wafGuard(page)` hook that records every response whose status is 403 or 500 and has header `server: awselb/2.0`. `test.afterEach` asserts that the list is empty, printing the URLs.
      - `rpc(request, model, method, args, kwargs)`: POST `/web/dataset/call_kw/${model}/${method}` with JSON-RPC 2.0 body `{jsonrpc:'2.0',method:'call',params:{model,method,args,kwargs}}`. It throws on `error` in the response. This works on Odoo 12–18.
      - `login(page)`: `goto('/web/login')`, fill `input[name=login]`=admin and `input[name=password]`=admin, click `button[type=submit]`, wait for the URL to match `/\/(web|odoo)/`.
    - Flows (each one `test(...)`, all with `wafGuard`):
      - **`backend.spec.ts`:**
        - login, then open `/web#action=contacts.action_contacts` (12–16) or `/odoo/contacts` (18), chosen by the version parsed from the project name, and wait for network idle;
        - open the CRM pipeline via `/web#model=crm.lead&view_type=kanban`;
        - log out via `/web/session/logout`.
      - **`rpc.spec.ts`**, after login, using `page.request` (it carries the cookies):
        - create a `res.partner` with `comment` = 40 KB of HTML (`'<p>Nota <b>cliente</b> <a href="https://example.com/x">link</a></p>'` repeated);
        - `write` it;
        - `search_read` partners with a domain containing `('name','ilike','select')`;
        - create an `ir.attachment` with `datas` = base64 of 200 KB of random bytes (`res_model` res.partner);
        - post a chatter message via `rpc(..., 'res.partner', 'message_post', [[id]], {body: '<p>ciao <script>x</script>?</p>', message_type: 'comment'})`. The script tag is legit editor content that Odoo escapes.
      - **`website.spec.ts`** (anonymous):
        - `goto('/')`, `/shop`, `/contactus`;
        - submit the contact form when its `form[action*="/website/form/"]` exists (fill name, email, subject, a question containing `UNION of interests; please DROP me a line` and `https://example.org` text). Otherwise mark the step `test.info().annotations` "no contact form".
        - fetch `/web/assets/…` CSS/JS through page load, which it does implicitly;
        - `GET /web/image/res.partner/1/avatar_128`.
    - `run.sh SITES`: generates RUN_ID, runs `docker compose -p waf -f deploy/compose/lab-tools.yml --profile tools run --rm -e SITES -e RUN_ID playwright`, and prints RUN_ID on the last line as `RUN_ID=<id>`.
    - Makefile: `lab-legit:` → `tests/legit/run.sh shop12,shop14,shop16,shop18`.
  - Steps:
    1. S1 — Write the package and lock.
    2. S2 — Config + helpers.
    3. S3 — Specs.
    4. S4 — Run `make lab-legit` with the profiles in place.
  - Failure handling:
    - a selector or URL that differs per version → branch on the version in the helper (document it);
    - a WAF block → do not change the test. Record it for 2.5 (profile tuning) and mark this unit BLOCKED on 2.5 only if more than the expected rule families block. Expected families are SizeRestrictions_BODY, CrossSiteScripting_BODY and GenericRFI_BODY, which odoo-common already counts.
- **Unit tests:** N/A — test code; validated by its own run.
- **e2e tests:** `make lab-legit` → all tests passed and wafGuard is empty. Cross-check: `jq` over today's `events.jsonl` for `request_headers` containing `<RUN_ID>-legit` and `action=="BLOCK"` → 0 rows (T-LEG1). G-U23.
- **Done:** G-U23 passes, or G-U23 is BLOCKED → resolved in 2.5 (then re-run).

### 2.4 Attack generators (nuclei, nikto) and lab matrix tooling
- **Agent:** agent-1
- **Assignment:** implement; self-review.
- **Files:**
  - NEW: `deploy/compose/lab-tools.yml` (add services `nuclei`, `nikto`), `lab/nikto/Dockerfile`, `scripts/lab-attack.sh`, `scripts/lab-matrix.sh`, `scripts/sql/matrix.sql`, `scripts/sql/legit.sql`.
  - WRITE: `Makefile` (`lab-attack`, `lab-matrix`).
- **Change:**
  - Preconditions: 2.3 DONE.
  - Contract:
    - `nuclei` service: image `projectdiscovery/nuclei:v3.11`, network `waf_lab`, volume `nuclei-templates:/root/nuclei-templates`. Command (set by the script) `-u http://waf:8080 -H 'Host: shopNN.lab.test' -H 'X-Waf-Test: <RUN_ID>-nuclei' -tags cve,lfi,xss,sqli,rce,exposure -severity medium,high,critical -rl 50 -silent -jsonl -o /out/nuclei-shopNN.jsonl`, with volume `../../build/lab:/out`.
    - `lab/nikto/Dockerfile`:
      ```dockerfile
      FROM alpine:3.22
      RUN apk add --no-cache perl perl-net-ssleay git && git clone --depth 1 --branch 2.6.1 https://github.com/sullo/nikto /opt/nikto
      ENTRYPOINT ["perl", "/opt/nikto/program/nikto.pl"]
      ```
      If tag `2.6.1` is not cloneable, check the tag list with `git ls-remote --tags https://github.com/sullo/nikto | tail` and record the actual tag in §6. Command: `-h http://waf:8080 -vhost shopNN.lab.test -useragent "Mozilla/5.0 nikto-lab <RUN_ID>-nikto" -Tuning 123489b -maxtime 600s -o /out/nikto-shopNN.txt`.
    - `lab-attack.sh SITES` runs both tools per site, sequentially, and prints `RUN_ID=`.
    - `lab-matrix.sh [--date YYYY-MM-DD] [--out build/lab/matrix.md] [--sql matrix.sql|legit.sql]` runs `docker run --rm -v $WAF_DATA_DIR/raw:/raw:ro -v $PWD/scripts/sql:/sql:ro clickhouse/clickhouse-server:26.8-alpine clickhouse local --queries-file /sql/matrix.sql`. The SQL reads `file('/raw/<date>/events.jsonl', JSONEachRow)` and `matches.jsonl` with the explicit schema copied from the column lists of `waf.events` / `waf.matches` in `snippets/clickhouse-ddl.sql`, without codecs or defaults. Pass the date via `--param_d`. Output `FORMAT Markdown`, with these sections:
      1. Per site: total, `action` counts, `aws_default_action` counts, and the disagreements where `action != aws_default_action`, split by `user_class`.
      2. Per rule (`matches`, `post_terminating=0`): match count per site and configured_action.
      3. Top 20 disagreement rows (site, path, terminating_rule, aws_default_rule).
      4. Legit runs (requests with header `x-waf-test` like `%-legit`): rows with action BLOCK (must be 0).
      5. Attack runs (`%-nuclei`, `%-nikto`): block rate per site.
    - `legit.sql` is the same as section 4 only, for gates (prints a count).
  - Steps:
    1. S1 — The tools compose and Dockerfile.
    2. S2 — The scripts and SQL.
    3. S3 — Run `make lab-attack lab-matrix`.
  - Failure handling: the nuclei templates download needs network; on failure BLOCKED with question to the user. A ClickHouse schema error → align the schema with `snippets/clickhouse-ddl.sql` (it is the source).
- **Unit tests:** N/A — scripts. Guarded by e2e.
- **e2e tests:** `make lab-matrix` exits 0 and `build/lab/matrix.md` contains the 5 headers. `scripts/lab-matrix.sh --sql legit.sql` prints `0`. G-U24.
- **Done:** G-U24 passes.

### 2.5 Profile tuning loop (fixed algorithm)
- **Agent:** agent-1
- **Assignment:** implement; self-review with the matrix as evidence.
- **Files:**
  - WRITE: `profiles/odoo-*.yaml`, `tests/odoo-exceptions.yaml`.
  - NEW: `docs/odoo.md`, `docs/lab-matrix-001.md` (a copy of the final matrix).
- **Change:**
  - Preconditions: 2.4 DONE.
  - Algorithm (repeat at most 5 iterations; record each in §6):
    1. Run `make lab-legit`. For every WAF block from legit (matrix section 4), take `(site, rule, path)`.
    2. For each one:
       - If the rule is already counted and blocked by a custom rule, extend that rule's negated regex with the minimal path prefix (a literal segment, never `.*`).
       - Otherwise add `rule_action_overrides: <Rule>: count` in the profile, plus a custom rule `Odoo<Rule>OutsideX` in the same shape as odoo-common.
       - A rule needed by all versions goes into odoo-common, otherwise into the version profile.
    3. Run `make test-odoo`. If a corpus attack now passes on an Odoo site:
       - if its path is outside the allowed prefixes, it is a bug → fix it;
       - if inside, add an exception with a reason (an accepted Odoo risk).
    4. Stop when legit = 0 blocks and test-odoo passes.

    Never use: `enabled: false` on a managed group, group-level `override_action: count`, scope-down excluding `/web`, or `path_overrides` (nginx-only).
  - `docs/odoo.md` (Italian):
    - the profile per version and why each override exists, with evidence rows from the matrix;
    - the exception list;
    - the realtime-path proxying;
    - how to tune a new Odoo module (the workflow from `docs/tuning.md`).
- **Unit tests:** T-PRF1 still passes (aws-compatible). G-U25.
- **e2e tests:** `make lab-legit` = 0 blocks; `make test-odoo` passes; `make test-e2e` (demo suite) still passes. G-U25.
- **Done:** G-U25 passes. If the iteration limit is reached without convergence → BLOCKED to agent-1 with the matrix.

## Phase gates and closure
- Required gates: G-U21..G-U25, then G-P2 (`make lab-up test-e2e test-odoo lab-legit lab-matrix` and `legit.sql` = 0).
- README obligation: add a "Lab Odoo" section to README (`make lab-up`, RAM requirement, `make lab-legit`, `make lab-attack`, `make lab-matrix`) in 2.5. Also `docs/odoo.md`.
- Every sub-phase DONE or SKIPPED with a reason. Run the full phase gates now.
- agent-1 reviews profile aws-compatibility (D27), the exceptions' reasons and the matrix.
- Open P2, record the review, mark DONE. Commit `phase(001/P2): PHASE 2 COMPLETE — Lab Odoo; gates and review passed`.
