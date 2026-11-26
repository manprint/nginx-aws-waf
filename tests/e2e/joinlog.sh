#!/usr/bin/env bash
# G-U17: joined event log (T-L1, I-6, I-7), volume (T-L2) and rotation.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
W="${WAFCTL:-$ROOT/wafctl/bin/wafctl}"
RAW="${WAF_DATA_DIR:-$ROOT/.run}/raw"
OHA="$(command -v oha || echo "$HOME/.cargo/bin/oha")"
ev() { cat "$RAW"/*/events.jsonl 2>/dev/null; }
mt() { cat "$RAW"/*/matches.jsonl 2>/dev/null; }
# events whose X-Waf-Test header (any case) starts with $1
sel() { ev | jq -c --arg p "$1" 'select(any(.request_headers | to_entries[]; (.key|ascii_downcase)=="x-waf-test" and (.value|startswith($p))))'; }
# wait until sel $1 has at least $2 events (max $3 s)
wait_n() { local i; for ((i=0; i<$3; i++)); do (( $(sel "$1" | wc -l) >= $2 )) && return 0; sleep 1; done; return 1; }

# T-L1: corpus → one joined event per case
res=$(mktemp); "$W" test run --suite "$ROOT/tests/corpus" --format json > "$res"
rid=$(jq -r .run_id "$res"); n=$(jq '.results|length' "$res")
check T-L1-corpus-ok test "$(jq '.passed' "$res")" = "$n"
sleep 6; wait_n "$rid-" "$n" 20
evs=$(mktemp); sel "$rid-" > "$evs"
check T-L1-one-event-per-case test "$(jq -r '.request_headers | to_entries[] | select((.key|ascii_downcase)=="x-waf-test") | .value' "$evs" | sort -u | wc -l)" = "$n"
check T-L1-event-count test "$(wc -l < "$evs")" = "$n"
bad=0; badm=0
while read -r c; do
  id=$(jq -r .id <<<"$c"); st=$(jq -r .status <<<"$c"); term=$(jq -r .term <<<"$c"); mode=$(jq -r .mode <<<"$c")
  e=$(jq -c --arg h "$rid-$id" 'select(any(.request_headers | to_entries[]; (.key|ascii_downcase)=="x-waf-test" and .value==$h))' "$evs" | head -1)
  [[ -z "$e" ]] && { echo "  no event for $id"; bad=$((bad+1)); continue; }
  act=$(jq -r .action <<<"$e"); tr=$(jq -r .terminating_rule <<<"$e"); ts=$(jq -r .ts <<<"$e"); req=$(jq -r .request_id <<<"$e")
  want=ALLOW; [[ "$st" == 403 && "$mode" == enforce ]] && want=BLOCK
  if [[ "$want" == BLOCK && "$act" != BLOCK ]] || [[ "$want" != BLOCK && "$act" == BLOCK ]]; then echo "  $id action=$act want=$want"; bad=$((bad+1)); fi
  if [[ "$term" == Default_Action ]]; then [[ "$tr" == Default_Action ]] || { echo "  $id term=$tr"; bad=$((bad+1)); }
  else [[ "$tr" == */"$term" ]] || { echo "  $id term=$tr want */$term"; bad=$((bad+1)); }; fi
  [[ "$ts" =~ Z$ ]] || { echo "  $id ts=$ts"; bad=$((bad+1)); }
  # a block by a rule has ≥ 1 matches row (a Default_Action block matched nothing)
  if [[ "$act" == BLOCK && "$tr" != Default_Action ]] && (( $(mt | grep -c "\"request_id\":\"$req\"") < 1 )); then echo "  $id no matches row"; badm=$((badm+1)); fi
done < <(jq -c '.results[]' "$res")
check T-L1-event-fields test "$bad" = 0
check T-L1-matches-rows test "$badm" = 0
rm -f "$res" "$evs"

# T-L2: 2000 requests → ≥ 2000 events
bid="bench-$(date +%s)"
"$OHA" -n 2000 -c 20 --no-tui -H "Host: demo.lab.test" -H "X-Waf-Test: $bid" -H "X-Forwarded-For: 198.51.100.10" "$WAF_URL/web/login" >/dev/null
check T-L2-2000-events wait_n "$bid" 2000 30

# rotation: forced rotate, a new request lands in the new audit.log and in events.jsonl
"$W" logs rotate --max-size 1 | grep -q '^rotated audit.log' && pass rotate-renamed || fail rotate-renamed
sleep 1
rot="rot-$(date +%s)"
curl -s -o /dev/null -H 'Host: demo.lab.test' -H "X-Waf-Test: $rot" "$WAF_URL/?q=<script>" -g
sleep 1
check rotate-new-audit grep -q "$rot" "$LOGS/audit.log"
check rotate-old-audit-closed bash -c "! grep -q '$rot' $LOGS/audit.log.2*"
check rotate-new-access grep -q 'demo.lab.test' "$LOGS/access.log"
check rotate-event wait_n "$rot" 1 20
check rotate-event-joined bash -c "$(declare -f ev sel); RAW='$RAW'; sel '$rot' | jq -e 'select(.terminating_rule | endswith(\"CrossSiteScripting_QUERYARGUMENTS\"))' >/dev/null"
finish
