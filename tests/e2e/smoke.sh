#!/usr/bin/env bash
# G-U14 smoke test of the running lab node.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
a0=$(stat -c %s "$LOGS/audit.log" 2>/dev/null || echo 0)
x0=$(stat -c %s "$LOGS/access.log" 2>/dev/null || echo 0)

code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: demo.lab.test' "$WAF_URL/")
check smoke-200 test "$code" = 200

tmp=$(mktemp); hdr=$(mktemp)
code=$(curl -s -o "$tmp" -D "$hdr" -w '%{http_code}' -A '' -H 'Host: demo.lab.test' "$WAF_URL/")
check smoke-403-status test "$code" = 403
check smoke-403-body cmp -s "$tmp" "$ROOT/waf/static/403.html"
check smoke-403-server grep -qi '^Server: awselb/2.0' "$hdr"
rm -f "$tmp" "$hdr"

curl -s -o /dev/null -H 'Host: unknown.test' "$WAF_URL/"; rc=$?
check smoke-unknown-host-444 test "$rc" = 52

# T-R12: site phase-2 action vars override main defaults (R2 ordering); tuned counts SizeRestrictions_BODY
body=$(head -c 9000 /dev/zero | tr '\0' 'a')
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: tuned.lab.test' -H 'Content-Type: text/plain' --data-binary "$body" "$WAF_URL/web/dataset/call_kw")
check T-R12-count-override test "$code" = 200
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: tuned.lab.test' -H 'Content-Type: text/plain' --data-binary "$body" "$WAF_URL/other")
check T-R12-label-custom-rule test "$code" = 403

sleep 1
a1=$(stat -c %s "$LOGS/audit.log" 2>/dev/null || echo 0)
x1=$(stat -c %s "$LOGS/access.log" 2>/dev/null || echo 0)
check smoke-audit-log-grows test "$a1" -gt "$a0"
check smoke-access-log-grows test "$x1" -gt "$x0"
finish
