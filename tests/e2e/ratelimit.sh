#!/usr/bin/env bash
# Rate-based rule (6.1): site ratelimit (10 req/60 s, block) and ratecount (same, count).
# Checks the HTTP status, the access-log "rl" ($limit_req_status) and the ClickHouse events.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
C="${WAF_CONFIG_DIR:-$ROOT/lab/config}"
source "$C/secrets.env"
LOG="${WAF_DATA_DIR:-$ROOT/.run}/logs/access.log"
chq() { curl -s -u "waf_admin:$WAF_CH_ADMIN_PASSWORD" http://127.0.0.1:8123/ --data-binary "$1"; }
burst() { # burst <site> <xff> <tag> → status codes, one per line
  for i in $(seq 1 40); do
    curl -s -o /dev/null -w '%{http_code}\n' -H "Host: $1.lab.test" -H "X-Forwarded-For: $2" "http://127.0.0.1:8080/rl/$3/$i"
  done; }
since=$(date -u +%Y-%m-%dT%H:%M:%S)
tag="rl$(date +%s)"
# a distinct client per run: limit_req state survives between runs (60 s window)
o=$(( $(date +%s) % 200 + 20 ))
IP_BLOCK="198.51.100.$o"; IP_COUNT="198.51.100.$((o + 1))"

codes=$(burst ratelimit "$IP_BLOCK" "$tag")
n403=$(grep -c '^403$' <<<"$codes"); n200=$(grep -c '^200$' <<<"$codes")
check "RL-block-some-403 ($n403 403, $n200 200 of 40)" test "$n403" -ge 1
check "RL-block-burst-allowed (first >= 10 are 200: $n200)" test "$n200" -ge 10
sleep 1
rej=$(grep -F "\"/rl/$tag/" "$LOG" | grep -F '"site":"ratelimit"' | grep -c '"rl":"REJECTED"')
check "RL-access-log-REJECTED ($rej = $n403)" test "$rej" = "$n403"

ctag="${tag}c"
codes=$(burst ratecount "$IP_COUNT" "$ctag")
c200=$(grep -c '^200$' <<<"$codes")
check "RL-count-all-200 ($c200 of 40)" test "$c200" = 40
sleep 1
dry=$(grep -F "\"/rl/$ctag/" "$LOG" | grep -c '"rl":"REJECTED_DRY_RUN"')
check "RL-count-access-log-DRY_RUN ($dry >= 1)" test "$dry" -ge 1

q="SELECT count() FROM waf.events WHERE site_id = 'ratelimit' AND startsWith(path, '/rl/$tag/') AND terminating_type = 'RATE_BASED' AND action = 'BLOCK' AND rate_limit_status = 'REJECTED'"
for ((t=0; t<40; t++)); do ev=$(chq "$q"); (( ${ev:-0} >= n403 )) && break; sleep 1; done
check "RL-events-RATE_BASED-BLOCK ($ev = $n403)" test "${ev:-0}" = "$n403"
q="SELECT countIf(action = 'BLOCK'), countIf(rate_limit_status = 'REJECTED_DRY_RUN') FROM waf.events WHERE site_id = 'ratecount' AND startsWith(path, '/rl/$ctag/')"
for ((t=0; t<40; t++)); do r=$(chq "$q"); [[ "$(cut -f2 <<<"$r")" -ge 1 ]] 2>/dev/null && break; sleep 1; done
check "RL-count-events-no-block-dry-run ($r)" bash -c "[[ \$(cut -f1 <<<'$r') == 0 && \$(cut -f2 <<<'$r') -ge 1 ]]"
finish
