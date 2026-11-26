#!/usr/bin/env bash
# G-U21: the four Odoo sites answer through the WAF.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
for v in 12 14 16 18; do
  H="Host: shop$v.lab.test"
  hdr=$(mktemp)
  code=$(curl -s -o /dev/null -D "$hdr" -w '%{http_code}' -H "$H" "$WAF_URL/web/login")
  check "shop$v-login-200" test "$code" = 200
  check "shop$v-server-not-awselb" bash -c "! grep -qi '^Server: awselb' '$hdr'"
  rm -f "$hdr"
  code=$(curl -s -o /dev/null -w '%{http_code}' -A '' -H "$H" "$WAF_URL/web/login")
  check "shop$v-noua-403" test "$code" = 403
  if (( v < 16 )); then
    code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' -H "$H" -H 'Content-Type: application/json' --data '{}' "$WAF_URL/longpolling/poll")
  else
    code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' -H "$H" "$WAF_URL/websocket")
  fi
  check "shop$v-realtime-not-403 ($code)" bash -c "[[ '$code' != 403 && '$code' != 000 ]]"
done
finish
