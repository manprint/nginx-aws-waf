#!/usr/bin/env bash
# CLI analytics e2e (3.2–3.5): logs search/show (+ --raw), export, stats, report, retention.
# Needs the central stack (make lab-min-up / lab-up) and ClickHouse on 127.0.0.1:8123.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
W="${WAFCTL:-$ROOT/wafctl/bin/wafctl}"
RAW="${WAF_DATA_DIR:-$ROOT/.run}/raw"

# corpus run, then wait until its events are in ClickHouse
corpus=$("$W" test run --suite "$ROOT/tests/corpus" --format json)
nblock=$(jq '[.results[] | select(.status == 403 and .mode == "enforce" and (.summary|test("site=demo;")))] | length' <<< "$corpus")
for ((i=0; i<30; i++)); do
  got=$("$W" logs search --since 15m --format json --limit 100000 --site demo --action BLOCK | jq length)
  (( got >= nblock )) && break; sleep 1
done

# --- 3.2 logs search / show / --raw (G-U32, T-Q5); --node: the raw dir holds only this node's
# events while ClickHouse also has lab-node-2's (tests/e2e/multinode.sh)
check "Q-search-blocks-demo ($got >= $nblock)" test "$got" -ge "$nblock"
one=$("$W" logs search --since 15m --site demo --action BLOCK --rule NoUserAgent_HEADER --format json --limit 1 | jq -r '.[0].request_id // empty')
check "Q-search-rule-filter" test -n "$one"
nm=$("$W" logs show "$one" --format json | jq '.matches | length')
check "Q-show-matches ($nm)" test "${nm:-0}" -ge 1
from=$(date -u -d '-15 min' +%Y-%m-%dT%H:%M:%SZ); to=$(date -u -d '-5 sec' +%Y-%m-%dT%H:%M:%SZ)
sleep 6
a=$("$W" logs search --from "$from" --to "$to" --node lab-node-1 --format json --limit 100000 | jq length)
b=$("$W" logs search --from "$from" --to "$to" --node lab-node-1 --format json --limit 100000 --raw "$RAW" | jq length)
check "T-Q5-raw-same-count ($a = $b)" test "$a" = "$b"

# --- 3.3 logs export (G-U33)
x=$(mktemp); "$W" logs export --from "$from" --to "$to" --node lab-node-1 --format aws -o "$x" 2>/dev/null
ok=$(jq -e .httpRequest.requestId "$x" >/dev/null && echo 1 || echo 0); xn=$(wc -l < "$x")
check "X-aws-lines-parse" test "$ok" = 1
check "X-aws-count-eq-search ($xn = $a)" test "$xn" = "$a"
check "X-aws-terminating-group" grep -q '"terminatingRule":{"ruleId":"NoUserAgent_HEADER","action":"BLOCK"}' "$x"
"$W" logs export --from "$from" --to "$to" --node lab-node-1 --format csv -o "$x" 2>/dev/null; cn=$(( $(wc -l < "$x") - 1 ))
check "X-csv-count ($cn = $a)" test "$cn" = "$a"
"$W" logs export --from "$from" --to "$to" --format jsonl --with-matches --gzip -o "$x" 2>/dev/null
jm=$(zcat "$x" | jq -s '[.[] | select(.match_count > 0 and (.matches|length) > 0)] | length')
check "X-jsonl-with-matches ($jm)" test "${jm:-0}" -gt 0
rm -f "$x"

# --- 3.4 stats (G-U34)
nua=$("$W" stats --since 15m --by rule --format json --top 1000 | jq '[.[] | select(.rule == "NoUserAgent_HEADER") | .matches] | add // 0')
check "S-rule-NoUserAgent ($nua)" test "$nua" -ge 1
nb=$(jq '[.results[] | select(.status == 403 and .mode == "enforce")] | length' <<< "$corpus")
ob=$("$W" stats --since 15m --format json | jq '.[0].block')
check "S-overview-block ($ob >= $nb)" test "$ob" -ge "$nb"
oa=$("$W" stats --since 2h --format json | jq '.[0].requests')
check "S-overview-agg ($oa >= $a)" test "$oa" -ge "$a"
cn=$("$W" stats --since 2h --by rule --counted --format json | jq '[.[] | select(.counted != .matches)] | length')
check "S-counted-only" test "$cn" = 0

# --- 3.5 report + retention + migrate (G-U35)
r="$ROOT/build/r.html"; rm -f "$r"
"$W" report --html --since 1h -o "$r" 2>/dev/null
sz=$(stat -c %s "$r" 2>/dev/null || echo 0)
check "H-report-size ($sz > 10240)" test "$sz" -gt 10240
check "H-report-no-external-refs" bash -c "! grep -Eiq '(src|href)=\"?(https?:)?//' '$r'"
check "H-report-NoUserAgent" grep -q NoUserAgent_HEADER "$r"
check "M-migrate-idempotent" bash -c "'$W' ch migrate | grep -q 'up to date'"
"$W" ch retention --raw-days 20 >/dev/null
check "M-retention-20" bash -c "'$W' ch retention | grep -Eq '^events +20 DAY'"
"$W" ch retention --raw-days 30 >/dev/null
check "M-retention-restored" bash -c "'$W' ch retention | grep -Eq '^matches +30 DAY'"
check "M-retention-agg-ge-raw" bash -c "! '$W' ch retention --agg-days 10 2>/dev/null"
finish
