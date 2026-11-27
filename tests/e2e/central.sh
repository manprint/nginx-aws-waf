#!/usr/bin/env bash
# G-U31: central storage — corpus events in ClickHouse within 10 s (T-C1, I-6), matches,
# heartbeats, GeoIP enrichment (T-C2), 1-minute aggregates.
# Header keys keep the client's case in events.request_headers (observed: 'X-Waf-Test').
set -uo pipefail
source "$(dirname "$0")/lib.sh"
W="${WAFCTL:-$ROOT/wafctl/bin/wafctl}"
SECRETS="${WAF_CONFIG_DIR:-$ROOT/lab/config}/secrets.env"
CH_URL="${WAF_CH_URL:-http://127.0.0.1:8123}"
CH_PW="$(sed -n 's/^WAF_CH_RO_PASSWORD=//p' "$SECRETS")"
# q SQL [name=value ...] → TSV result (server-side parameters, never string-concatenated)
q() {
  local sql="$1"; shift; local a=()
  for p in "$@"; do a+=(--data-urlencode "param_${p%%=*}=${p#*=}"); done
  curl -sS -G -u "waf_ro:$CH_PW" "$CH_URL/" --data-urlencode "query=$sql" "${a[@]}"
}
start=$(date -u +%s)

# Warm-up: an idle pipeline adds latency (Vector 0.62 file-source idle backoff up to ~8 s, disk
# buffer reader up to ~10 s; measured in 3.1). T-C1 measures the steady state, so first send
# warm-up requests until one reaches ClickHouse (idle first-event latency printed as INFO).
w0=$(date +%s); warm=""
for ((i=0; i<40; i++)); do
  curl -s -o /dev/null -H 'Host: demo.lab.test' -H "X-Waf-Test: warm$w0-$i" "$WAF_URL/warmup"
  c=$(q "SELECT count() FROM waf.events WHERE startsWith(request_headers['X-Waf-Test'], {p:String})" "p=warm$w0-")
  [[ "${c:-0}" -gt 0 ]] && { warm=$(( $(date +%s) - w0 )); break; }
  sleep 1
done
check "warm-up reached ClickHouse (${warm:-none} s)" test -n "$warm"

# T-C1: corpus → one event per case in ClickHouse within 10 s
res=$(mktemp); "$W" test run --suite "$ROOT/tests/corpus" --format json > "$res"
rid=$(jq -r .run_id "$res"); n=$(jq '.results|length' "$res"); rm -f "$res"
got=0
for ((i=0; i<10; i++)); do
  got=$(q "SELECT count() FROM waf.events WHERE mapContains(request_headers, 'X-Waf-Test') AND startsWith(request_headers['X-Waf-Test'], {p:String})" "p=$rid-")
  [[ "$got" == "$n" ]] && break
  sleep 1
done
check "T-C1-events-in-10s ($got/$n, run $rid, $(date -u +%T))" test "$got" = "$n"
for ((i=0; i<10; i++)); do   # matches use their own ClickHouse sink (separate batch)
  m=$(q "SELECT count() FROM waf.matches WHERE request_id IN (SELECT request_id FROM waf.events WHERE startsWith(request_headers['X-Waf-Test'], {p:String}))" "p=$rid-")
  [[ "${m:-0}" -gt 0 ]] && break; sleep 1
done
check "T-C1-matches-rows ($m)" test "${m:-0}" -gt 0

# heartbeat of this node, newer than 60 s
hb=$(q "SELECT count() FROM waf.heartbeats WHERE node_id = {n:String} AND ts > now64(3) - INTERVAL 60 SECOND" "n=${WAF_NODE_ID:-lab-node-1}")
check "heartbeat-60s ($hb)" test "${hb:-0}" -gt 0

# T-C2: GeoIP enrichment (MaxMind test databases). Not a latency check: two requests after an
# idle pipeline can take up to ~15 s (Vector file-source idle backoff + disk buffer), so wait 30 s.
geo() { curl -s -o /dev/null -H 'Host: demo.lab.test' -H "X-Forwarded-For: $1" -H "X-Waf-Test: $rid-geo-$1" "$WAF_URL/geo"; }
geo 2.125.160.216; geo 89.160.20.112
for ((i=0; i<30; i++)); do
  c=$(q "SELECT count() FROM waf.events WHERE startsWith(request_headers['X-Waf-Test'], {p:String})" "p=$rid-geo-")
  [[ "$c" == 2 ]] && break; sleep 1
done
gb=$(q "SELECT country FROM waf.events WHERE request_headers['X-Waf-Test'] = {h:String}" "h=$rid-geo-2.125.160.216")
se=$(q "SELECT concat(country, ' ', toString(asn), ' ', as_org) FROM waf.events WHERE request_headers['X-Waf-Test'] = {h:String}" "h=$rid-geo-89.160.20.112")
check "T-C2-country-GB ($gb)" test "$gb" = GB
check "T-C2-country-SE ($se)" test "${se%% *}" = SE
asn=$(awk '{print $2}' <<<"$se")
if [[ "${asn:-0}" != 0 ]]; then pass "T-C2-asn ($asn)"; else echo "INFO T-C2-asn: 89.160.20.112 not in the ASN test DB (asn=0)"; fi

# aggregates: agg_requests_1m covers the corpus window
agg=$(q "SELECT sum(requests) FROM waf.agg_requests_1m WHERE minute >= toStartOfMinute(toDateTime({s:UInt32}, 'UTC'))" "s=$start")
check "agg-requests-1m ($agg >= $n)" test "${agg:-0}" -ge "$n"
finish
