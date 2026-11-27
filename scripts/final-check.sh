#!/usr/bin/env bash
# G-FINAL: the reference scenario of plan 001 (overview), steps 1–8 in order, fail fast.
# Prints "G-FINAL step N OK" per step. Needs the lab host (Docker, network for Odoo images and
# the terraform provider), lab/config with the four Odoo sites. Run: make final-check
set -uo pipefail
export LC_NUMERIC=C
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source scripts/lab-env.sh
export WAF_COMPOSE_EXTRA=deploy/compose/lab-min.yml:deploy/compose/lab.yml
W="$ROOT/wafctl/bin/wafctl"
WAF_URL="${WAF_URL:-http://127.0.0.1:8080}"
source "$WAF_CONFIG_DIR/secrets.env"
LOGDIR="$ROOT/build/final-check"; mkdir -p "$LOGDIR"
chq() { curl -s -u "waf_admin:$WAF_CH_ADMIN_PASSWORD" http://127.0.0.1:8123/ --data-binary "$1"; }
die() { echo "G-FINAL step $1 FAILED: $2" >&2; echo "logs: $LOGDIR" >&2; exit 1; }
ok() { echo "G-FINAL step $1 OK${2:+ ($2)}"; }
BYPASS=0
cleanup() { (( BYPASS )) && "$W" bypass clear shop18 >/dev/null 2>&1; }
trap cleanup EXIT

# 1. lab up + corpus
make lab-up >"$LOGDIR/1-lab-up.log" 2>&1 || die 1 "make lab-up (see 1-lab-up.log)"
"$W" test run --suite tests/corpus --format json >"$LOGDIR/1-corpus.json" 2>"$LOGDIR/1-corpus.err" \
  || die 1 "corpus: $(jq -r '"\(.passed)/\(.total)"' "$LOGDIR/1-corpus.json" 2>/dev/null) passed"
t1=$(date +%s.%N)
rid=$(jq -r .run_id "$LOGDIR/1-corpus.json"); total=$(jq -r .total "$LOGDIR/1-corpus.json")
[[ "$(jq -r .passed "$LOGDIR/1-corpus.json")" == "$total" && "$total" -gt 0 ]] || die 1 "corpus not all passed"
# events of this run in ClickHouse (step 3 asserts the delay, measured here)
q="SELECT count() FROM waf.events WHERE startsWith(request_headers['X-Waf-Test'], '$rid-')"
while :; do
  n=$(chq "$q"); ch_delay=$(echo "$(date +%s.%N) - $t1" | bc)
  (( ${n:-0} >= total )) && break
  (( $(echo "$ch_delay > 10" | bc) )) && break
  sleep 0.2
done
ok 1 "corpus $total/$total, run $rid"

# 2. Playwright legit flows on the Odoo sites
make lab-legit >"$LOGDIR/2-legit.log" 2>&1 || die 2 "make lab-legit (see 2-legit.log)"
ok 2 "$(grep -Eo '[0-9]+ passed' "$LOGDIR/2-legit.log" | tail -1)"

# 3. ClickHouse within 10 s, stats, dashboards
(( ${n:-0} >= total )) || die 3 "only ${n:-0}/$total events of run $rid in ClickHouse after 10 s"
(( $(echo "$ch_delay <= 10" | bc) )) || die 3 "events of run $rid took ${ch_delay} s (> 10 s)"
s=$("$W" stats --since 15m --format json) || die 3 "wafctl stats"
[[ "$(jq '.[0].requests // 0' <<<"$s")" -gt 0 ]] || die 3 "wafctl stats --since 15m is empty"
scripts/check-dashboards.sh >"$LOGDIR/3-dashboards.log" 2>&1 || die 3 "check-dashboards (see 3-dashboards.log)"
ok 3 "$n events in $(printf '%.1f' "$ch_delay") s; stats $(jq -c '.[0] | {requests, block}' <<<"$s"); $(grep -c '^OK' "$LOGDIR/3-dashboards.log") panel queries"

# 4. self-contained HTML report
r=build/final-report.html
"$W" report --html --since 1h -o "$r" >/dev/null 2>&1 || die 4 "wafctl report"
[[ -s "$r" ]] || die 4 "empty report"
grep -Eiq '(src|href)="?(https?:)?//' "$r" && die 4 "report has external references"
ok 4 "$r $(stat -c %s "$r") B"

# 5. AWS log-format export
x=build/final-aws.jsonl
"$W" logs export --since 1h --format aws -o "$x" >/dev/null 2>&1 || die 5 "wafctl logs export"
lines=$(wc -l <"$x"); withid=$(jq -c 'select((.httpRequest.requestId // "") != "")' "$x" | wc -l)
(( lines > 0 && lines == withid )) || die 5 "$withid of $lines lines have httpRequest.requestId"
ok 5 "$x $lines lines"

# 6. bypass: attack passes, logged with shadow_action=BLOCK
"$W" bypass shop18 --ttl 10m --reason final-check >"$LOGDIR/6-bypass.log" 2>&1 || die 6 "wafctl bypass"
BYPASS=1
tag="fc$(date +%s)"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: shop18.lab.test' -H 'X-Forwarded-For: 198.51.100.77' \
  "$WAF_URL/$tag?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
q="SELECT shadow_action, action, terminating_rule FROM waf.events WHERE site_id = 'shop18' AND path = '/$tag' FORMAT TSV"
for ((i=0; i<30; i++)); do ev=$(chq "$q"); [[ -n "$ev" ]] && break; sleep 1; done
"$W" bypass clear shop18 >>"$LOGDIR/6-bypass.log" 2>&1 || die 6 "wafctl bypass clear"
BYPASS=0
[[ "$code" != 403 && "$(cut -f1 <<<"$ev")" == BLOCK ]] || die 6 "status $code, event '$ev'"
after=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: shop18.lab.test' -H 'X-Forwarded-For: 198.51.100.77' \
  "$WAF_URL/$tag-after?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
[[ "$after" == 403 ]] || die 6 "after bypass clear the attack returns $after"
ok 6 "attack $code under bypass, event $(tr '\t' ' ' <<<"$ev"); 403 after clear"

# 7. block spike alert reaches apprise (alert-sink)
tests/e2e/alerts.sh --spike-only >"$LOGDIR/7-alerts.log" 2>&1 || die 7 "alerts.sh --spike-only (see 7-alerts.log)"
ok 7 "$(grep -o 'after [0-9]* s' "$LOGDIR/7-alerts.log" | head -1)"

# 8. Terraform export of shop18
tf=build/aws/shop18.tf
"$W" export-aws --site shop18 --format terraform --allow-lossy -o "$tf" 2>"$LOGDIR/8-export.err" || die 8 "export-aws"
lossy=$(sed -n 's/^# lossy (not exported): //p' "$tf" | paste -sd,)
[[ "$lossy" == "client_ip.source=xff" ]] || die 8 "lossy list '$lossy' != client_ip.source=xff"
v=$(scripts/tf-validate-export.sh "$tf" 2>&1 | tail -1)
[[ "$v" == VALID ]] || die 8 "terraform validate: $v"
ok 8 "$tf VALID, lossy=$lossy"
