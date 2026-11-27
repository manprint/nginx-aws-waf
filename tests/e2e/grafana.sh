#!/usr/bin/env bash
# Grafana (4.2): provisioning, datasources, dashboards, panel queries, wafctl grafana user add|list.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
WAFCTL="${WAFCTL:-$ROOT/wafctl/bin/wafctl}"
SECRETS="${WAF_CONFIG_DIR:-$ROOT/lab/config}/secrets.env"
PW="${GF_ADMIN_PASSWORD:-$(sed -n 's/^GF_ADMIN_PASSWORD=//p' "$SECRETS")}"
GU="${WAF_GRAFANA_URL:-http://127.0.0.1:3000}"
g() { curl -s -u "admin:$PW" "$GU$1" "${@:2}"; }
for ((i=0; i<60; i++)); do [[ "$(g /api/health | jq -r .database 2>/dev/null)" == ok ]] && break; sleep 2; done
folder=$(g /api/folders | jq -r '.[] | select(.title == "WAF") | .uid')
n=$(g "/api/search?folderUIDs=$folder&type=dash-db" | jq -r '[.[].uid] | sort | join(",")')
check "GF-4-dashboards ($n)" test "$n" = "waf-explorer,waf-nodes,waf-overview,waf-tuning"
check "GF-ds-ch-health" test "$(g /api/datasources/uid/ch/health | jq -r .status)" = OK
check "GF-ds-prom-health" test "$(g /api/datasources/uid/prom/health | jq -r .status)" = OK
check "GF-anonymous-401" test "$(curl -s -o /dev/null -w '%{http_code}' "$GU/api/search")" = 401
if GF_ADMIN_PASSWORD="$PW" "$ROOT/scripts/check-dashboards.sh" > /tmp/check-dashboards.out 2>&1; then
  pass "GF-check-dashboards ($(grep -c '^OK ' /tmp/check-dashboards.out) queries)"
else fail "GF-check-dashboards" "$(grep -m3 FAIL /tmp/check-dashboards.out)"; fi
login="e2e-viewer-$$"
out=$("$WAFCTL" grafana user add "$login" --role Viewer 2>&1)
upw=$(sed -n 's/^password: //p' <<<"$out")
check "GF-user-add-generated-pw" test "${#upw}" -eq 20
check "GF-user-list" grep -q "^[0-9]* *$login .* Viewer$" <<<"$("$WAFCTL" grafana user list)"
check "GF-viewer-sees-dashboards" test "$(curl -s -u "$login:$upw" "$GU/api/search?type=dash-db" | jq length)" -ge 4
check "GF-viewer-cannot-write" test "$(curl -s -o /dev/null -w '%{http_code}' -u "$login:$upw" -X POST -H 'Content-Type: application/json' -d '{"dashboard":{"title":"x"},"overwrite":true}' "$GU/api/dashboards/db")" = 403
check "GF-user-dup-rejected" bash -c "! '$WAFCTL' grafana user add '$login' --role Viewer >/dev/null 2>&1"
id=$(g /api/org/users | jq -r --arg l "$login" '.[] | select(.login == $l) | .userId')
[[ -n "$id" ]] && g "/api/admin/users/$id" -X DELETE >/dev/null
finish
