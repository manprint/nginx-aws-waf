# nginx AWS WAF — State

Format: pev-state 2
Plan 001 rev 1 · repo /home/fabio/Scrivania/nginx_aws_waf · baseline unborn branch `main` (no commits; unit 0.1 makes the first commit) · updated 27-11-2026 00:46 UTC by agent-1:opus
§0 Protocol: without this skill read PROTOCOL.md once. History: history.md (append-only, never read to resume).

## 1. Now
- Run: execute 001 · result RUNNING · style handoff · acting as agent-1:opus
- Settings: autonomy true (plan) · WIP on (plan) · deadline none
- Stop latch: none
- Scope: plan 001 · RUNNING · overrides none
- Unit: plan PLAN/1 · OPEN · step S1 · assigned agent-1 → actual agent-1:opus
- Base: HEAD 7893ede + clean tree · branch main · last WIP tree none
- Last closure: unit:P6:1
- Next: close PLAN (G-FINAL) · next eligible: PLAN
- Owner: agent-1:opus active since 26-11-2026 22:35 UTC

## 2. Readiness
READY rev 1. agent-1 validated all 7 phase files, 39 sub-phases, the dependencies and the gate registry against the quality checklist ("Plan readiness"). Open questions: none. Required unverified claims: none. R1, R3, R5-addendum and R6-residual are `ACCEPTED (autonomous)` with guards (overview).

## 3. Settings, roster, gates
- **Roster:** agent-1:opus (supervisor and sole implementer; reviews are labelled `self-review`).
- **Plan defaults:** autonomy true · WIP on · executor power low. Set by Plan 26-11-2026, all explicit in the invocation.
- **Setup:**
  - Host: Ubuntu, Docker + Compose v5.8, Go 1.27.3 at `/usr/local/go/bin/go`, python3 + PyYAML 6.0.1, aws-cli 2.35.21, `oha` at `~/.cargo/bin/oha`, 46 GB RAM, 16 cores.
  - Network is allowed: image pulls, Go module download, CRS/IP/GeoIP/nuclei templates, Terraform providers.
  - All gate commands run from the repo root after `source scripts/lab-env.sh` (created in 0.1).
  - Lab ports: 8080/8443 (node), 18080/18443 (node2), 127.0.0.1:8123 (ClickHouse), 127.0.0.1:3000 (Grafana), 6000/6001 (ingress/pki).
  - Free them from stale probe containers: `docker ps -a --filter name=pev -q | xargs -r docker rm -f`.
  - Cleanup: `make lab-down`; `make lab-reset FORCE=1` wipes the lab volumes (lab data only).
  - AWS: none needed. An MFA session is only for the optional R1 check (§10).
- **Supervisor access:** single session (style handoff). agent-1 implements and self-reviews.

| Gate | Active from | Command (cwd = repo root, lab env sourced) | Must assert / discover |
|------|-------------|---------------|------------------------|
| G-BASE | baseline | `bash -n scripts/*.sh && git status --porcelain` | the 5 untracked baseline paths are listed (`.gitignore README.md data/ docs/ scripts/`); no tests exist yet |
| G-U01 | 0.1 | `make help && git check-ignore build/x .run/x a.pem \| wc -l && git ls-files \| wc -l` | 3 ignored; ≥ 30 files tracked |
| G-U02 | 0.2 | `wc -l waf/data/*.data && diff <(tail -n +2 docs/plans/001_plan-nginx-aws-waf/snippets/catalog-rules.yaml) waf/catalog/rules.yaml` | 79/11/11 lines; empty diff |
| G-U03 | 0.3 | `cd wafctl && go vet ./... && go test ./internal/catalog -run 'TestCAT[12]_' -v` + `wafctl catalog list \| wc -l` | 2 PASS; 56 lines |
| G-U04 | 0.4 | `cd wafctl && go test ./internal/config -run 'TestCFG[1-7]_' -v` | 7 PASS |
| G-U05 | 0.5 | `cd wafctl && go test ./internal/config -run 'TestVAL|TestCMP1_' -v` + `wafctl validate --config lab/config` | ≥ 15 PASS; prints `site demo: nginx-only (client_ip.source=xff)` |
| G-P0 | P0 | `make wafctl test-unit && wafctl validate --config lab/config` | all Go tests pass, count > 0 |
| G-NGXT | 1.1 | `scripts/ngx-test.sh [--modsec-only] <rendered dir>` | `syntax is ok` + `test is successful` in the D1 image |
| G-U11 | 1.1 | `cd wafctl && go test ./internal/render -run 'TestR[123]_' -v` | 3 PASS (T-R1 must not SKIP: python3+PyYAML present) |
| G-U12 | 1.2 | `… -run 'TestR[4-8]_' -v` + G-NGXT | 5 PASS |
| G-U13 | 1.3 | `… -run 'TestR(9\|10\|11)_' -v` + G-NGXT full | 3 PASS |
| G-U14 | 1.4 | `make lab-min-up && tests/e2e/smoke.sh` | all PASS lines |
| G-U15 | 1.5 | `cd wafctl && go test ./internal/apply ./internal/bypass -run 'TestA[12]_\|TestB[12]_' -v` + `tests/e2e/apply.sh` | 4 PASS; script PASS |
| G-U16 | 1.6 | `go test ./internal/testrun -run 'TestT[123]_' -v` + `make test-e2e` | 3 PASS; `PASSED n/n`, n ≥ 60 |
| G-U17 | 1.7 | `go test ./internal/logs -run TestL0_ -v` + `tests/e2e/joinlog.sh` | T-L0, T-L1, T-L2, rotate PASS |
| G-PERF | 1.8, PLAN | `scripts/bench.sh` | exit 0 (D29 thresholds); CSV recorded |
| G-U19 | 1.9 | `go test ./internal/catalog -run TestCAT3_ -v` | 1 PASS; docs reviewed |
| G-P1 | P1 | `make test-unit && make lab-min-up && make test-e2e && tests/e2e/smoke.sh && tests/e2e/apply.sh && tests/e2e/joinlog.sh` + G-PERF | all pass |
| G-U21 | 2.1 | `go test ./internal/config -run TestPRF1_ -v` + `make lab-up && tests/e2e/lab-smoke.sh` | PASS for 4 Odoo sites |
| G-U22 | 2.2 | `go test ./internal/testrun -run 'TestT[45]_' -v` + `make test-odoo` | 4 sites PASSED |
| G-U23 | 2.3 | `make lab-legit` + T-LEG1 jq check | all specs pass; 0 BLOCK events for the RUN_ID |
| G-U24 | 2.4 | `make lab-attack lab-matrix` + `scripts/lab-matrix.sh --sql legit.sql` | 5 sections; prints `0` |
| G-U25 | 2.5 | `make lab-legit test-odoo test-e2e` + TestPRF1 | all pass |
| G-P2 | P2 | `make lab-up test-e2e test-odoo lab-legit lab-matrix` + legit.sql = 0 | all pass |
| G-U31 | 3.1 | `go test ./internal/render -run TestC0_ -v` + `tests/e2e/central.sh` | T-C1, T-C2, heartbeat, agg PASS |
| G-U32 | 3.2 | `go test ./internal/ch ./internal/logs -run 'TestQ[1-4]_' -v` + 3.2 e2e | 4 PASS; T-Q5 |
| G-U33 | 3.3 | `go test ./internal/logs -run 'TestX[12]_' -v` + export e2e | 2 PASS; counts equal |
| G-U34 | 3.4 | `go test ./internal/stats -run 'TestS[1-3]_' -v` + stats e2e | 3 PASS |
| G-U35 | 3.5 | `go test ./internal/report ./internal/ch -run 'TestH[12]_\|TestM1_' -v` + `tests/e2e/cli.sh` | 3 PASS; report and retention checks |
| G-U36 | 3.6 | copy-paste check of the doc commands on the lab | self-review evidence |
| G-P3 | P3 | `make test-unit && make lab-up test-e2e && tests/e2e/central.sh && tests/e2e/cli.sh` | all pass |
| G-U41 | 4.1 | `go test ./internal/central -run 'TestCEN[12]_' -v` + the Prometheus `up` query | 2 PASS; 3 targets up; nginx series present |
| G-U42 | 4.2 | `go test ./internal/central -run TestG1_ -v && python3 scripts/gen-dashboards.py --check && scripts/check-dashboards.sh` | 4 dashboards; all panels OK; DS health OK |
| G-U43 | 4.3 | `go test ./internal/central -run 'TestAL[12]_' -v && tests/e2e/alerts.sh` | T-AL3/4/5 PASS |
| G-U44 | 4.4 | docs review | self-review evidence |
| G-P4 | P4 | `make lab-up && scripts/check-dashboards.sh && tests/e2e/alerts.sh` | all pass |
| G-U51 | 5.1 | `go test ./internal/pki -run 'TestPKI[1-5]_' -v` + openssl checks | 5 PASS |
| G-U52 | 5.2 | `go test ./internal/central ./internal/render -run 'TestING1_\|TestFWD1_' -v` + `tests/e2e/multinode.sh part1` | 2 PASS; T-MN1 |
| G-U53 | 5.3 | `go test ./internal/pki ./internal/node -run 'TestSRV[1-4]_\|TestND1_' -v` + `tests/e2e/multinode.sh` | 5 PASS; T-MN2..5 |
| G-U54 | 5.4 | `go test ./internal/node -run 'TestBS[12]_' -v && tests/e2e/bootstrap.sh` | 2 PASS; script PASS |
| G-U55 | 5.5 | `make tf-validate` | `Success!` |
| G-SEC | 5.x, P5, PLAN | `git ls-files \| grep -E '(\.pem\|\.key\|secrets\.env\|tokens\.json\|apprise-urls\.txt)$' \| grep -vx 'lab/config/apprise-urls.txt'` and the same over `git log --all --name-only --format=` | both empty |
| G-P5 | P5 | `make test-unit && make lab-up && tests/e2e/multinode.sh && tests/e2e/bootstrap.sh && make tf-validate` + G-SEC | all pass |
| G-U61 | 6.1 | `go test ./internal/render -run 'TestR1[34]_' -v && make test-e2e && tests/e2e/ratelimit.sh` | 2 PASS; corpus incl. optional.yaml; RATE_BASED |
| G-U62 | 6.2 | `go test ./internal/awsexport -run 'TestEXP[1-6]_' -v` + the T-EXP7 loop | 6 PASS; every lab site VALID |
| G-U63 | 6.3 | `go test ./internal/awsexport -run 'TestTF[1-3]_' -v` + `scripts/tf-validate-export.sh build/aws/shop18.tf` | 3 PASS; VALID |
| G-U64 | 6.4 | `go test ./internal/lists -run 'TestLST[1-3]_' -v` + `wafctl lists update` | 3 PASS; table + corpus iprep PASS |
| G-U65 | 6.5 | `make final-check` | 8 × `G-FINAL step N OK` |
| G-P6 | P6 | `make test-unit && make final-check` | all pass |
| G-FINAL | PLAN | `make final-check && scripts/bench.sh` + G-SEC | reference scenario steps 1–8 (overview) + G-PERF |

## 4. Unsettled ledger
none

## 5. Owned files
none

## 6. Checkpoint
none

## 7. Open-phase evidence
none

## 8. Revisions and decisions still needed
none

## 9. Blockers
none

## 10. Do-not-repeat
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

## 11. Board
| Phase | Status | Attempt | Sub-phases | Closure ref |
|-------|--------|---------|------------|-------------|
| 0 | DONE | 1 | 0.1–0.5 | unit:P0:1 |
| 1 | DONE | 1 | 1.1–1.9 | unit:P1:1 |
| 2 | DONE | 1 | 2.1–2.5 | unit:P2:1 |
| 3 | DONE | 1 | 3.1–3.6 | unit:P3:1 |
| 4 | DONE | 1 | 4.1–4.4 | unit:P4:1 |
| 5 | DONE | 1 | 5.1–5.5 | unit:P5:1 |
| 6 | DONE | 1 | 6.1–6.5 | unit:P6:1 |
| PLAN | IN_PROGRESS | 1 | — | — |

Phase 1: DONE (unit:P1:1), 1.1–1.9 DONE attempt 1.

Phase 2: DONE (unit:P2:1), 2.1–2.5 DONE attempt 1.

Phase 3: DONE (unit:P3:1), 3.1–3.6 DONE attempt 1.

Phase 4: DONE (unit:P4:1), 4.1–4.4 DONE attempt 1.

Phase 5: DONE (unit:P5:1), 5.1–5.5 DONE attempt 1.

Phase 6: DONE (unit:P6:1), 6.1–6.5 DONE attempt 1.

Phase 6 (expanded):
| ID | Depends | Status | Attempt | Assigned | Ref / note |
|----|---------|--------|---------|----------|------------|
| 6.1 | P1, P3 | DONE | 1 | agent-1 | unit:6.1:1 |
| 6.2 | 6.1 | DONE | 1 | agent-1 | unit:6.2:1 |
| 6.3 | 6.2 | DONE | 1 | agent-1 | unit:6.3:1 |
| 6.4 | 6.3 | DONE | 1 | agent-1 | unit:6.4:1 |
| 6.5 | 6.4 | DONE | 1 | agent-1 | unit:6.5:1 |
| P6 | 6.1–6.5 | DONE | 1 | agent-1 | unit:P6:1 |

README obligation: 1.9 (README rewrite), then 2.5, 3.6, 4.4, 5.5 and 6.5 add sections.
Open corrections: none. Open audits: none.
Statuses: TODO, IN_PROGRESS, IN_REVIEW, DONE, SKIPPED (reason kept), BLOCKED.

## 12. Suspended implementation
none
