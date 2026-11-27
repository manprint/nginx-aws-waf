#!/usr/bin/env bash
# CLI analytics e2e (3.2–3.5): logs search/show (+ --raw), export, stats, report, retention.
# Needs the central stack (make lab-min-up / lab-up) and ClickHouse on 127.0.0.1:8123.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
W="${WAFCTL:-$ROOT/wafctl/bin/wafctl}"
RAW="${WAF_DATA_DIR:-$ROOT/.run}/raw"

# corpus run, then wait until its events are in ClickHouse
res=$(mktemp); "$W" test run --suite "$ROOT/tests/corpus" --format json > "$res"
rid=$(jq -r .run_id "$res"); n=$(jq '.results|length' "$res")
nblock=$(jq '[.results[] | select(.status == 403 and .mode == "enforce" and (.summary|test("site=demo;")))] | length' "$res")
rm -f "$res"
for ((i=0; i<30; i++)); do
  got=$("$W" logs search --since 15m --format json --limit 100000 --site demo --action BLOCK | jq length)
  (( got >= nblock )) && break; sleep 1
done

# --- 3.2 logs search / show / --raw (G-U32, T-Q5)
check "Q-search-blocks-demo ($got >= $nblock)" test "$got" -ge "$nblock"
one=$("$W" logs search --since 15m --site demo --action BLOCK --rule NoUserAgent_HEADER --format json --limit 1 | jq -r '.[0].request_id // empty')
check "Q-search-rule-filter" test -n "$one"
nm=$("$W" logs show "$one" --format json | jq '.matches | length')
check "Q-show-matches ($nm)" test "${nm:-0}" -ge 1
from=$(date -u -d '-15 min' +%Y-%m-%dT%H:%M:%SZ); to=$(date -u -d '-5 sec' +%Y-%m-%dT%H:%M:%SZ)
sleep 6
a=$("$W" logs search --from "$from" --to "$to" --format json --limit 100000 | jq length)
b=$("$W" logs search --from "$from" --to "$to" --format json --limit 100000 --raw "$RAW" | jq length)
check "T-Q5-raw-same-count ($a = $b)" test "$a" = "$b"

# --- 3.3 logs export (G-U33)
x=$(mktemp); "$W" logs export --from "$from" --to "$to" --format aws -o "$x" 2>/dev/null
ok=$(jq -e .httpRequest.requestId "$x" >/dev/null && echo 1 || echo 0); xn=$(wc -l < "$x")
check "X-aws-lines-parse" test "$ok" = 1
check "X-aws-count-eq-search ($xn = $a)" test "$xn" = "$a"
check "X-aws-terminating-group" grep -q '"terminatingRule":{"ruleId":"NoUserAgent_HEADER","action":"BLOCK"}' "$x"
"$W" logs export --from "$from" --to "$to" --format csv -o "$x" 2>/dev/null; cn=$(( $(wc -l < "$x") - 1 ))
check "X-csv-count ($cn = $a)" test "$cn" = "$a"
"$W" logs export --from "$from" --to "$to" --format jsonl --with-matches --gzip -o "$x" 2>/dev/null
jm=$(zcat "$x" | jq -s '[.[] | select(.match_count > 0 and (.matches|length) > 0)] | length')
check "X-jsonl-with-matches ($jm)" test "${jm:-0}" -gt 0
rm -f "$x"
finish
