#!/usr/bin/env bash
# G-U15: apply safety (I-5), bypass and explain on the running lab node.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
W="${WAFCTL:-$ROOT/wafctl/bin/wafctl}"
CUR="${WAF_DATA_DIR:-$ROOT/.run}/runtime/current"
cfg="${WAF_CONFIG_DIR:-$ROOT/lab/config}"
before=$(readlink "$CUR")
demo() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: demo.lab.test' "$@" "$WAF_URL/"; }

# 1. validation error → exit 2, current unchanged
tmp=$(mktemp -d); cp -r "$cfg"/. "$tmp"/; rm -rf "$tmp/state"
cat > "$tmp/sites/broken.yaml" <<'Y'
version: 1
site_id: broken
server_names: ["bad name"]
app: generic
upstream: {servers: ["echo:8081"]}
Y
"$W" apply --config "$tmp" >/dev/null 2>&1; rc=$?
check apply-validation-exit2 test "$rc" = 2
check apply-validation-current-unchanged test "$(readlink "$CUR")" = "$before"
rm -rf "$tmp"

# 2. nginx -t failure → exit 1, current and service unchanged
WAF_TEST_INJECT=1 "$W" apply >/dev/null 2>&1; rc=$?
check apply-ngxt-exit1 test "$rc" = 1
check apply-ngxt-current-unchanged test "$(readlink "$CUR")" = "$before"
check apply-ngxt-still-serving test "$(demo)" = 200

# 3. bypass → count mode, then clear → block again
"$W" bypass demo --ttl 2m --reason e2e >/dev/null 2>&1
check bypass-allows test "$(demo -A '')" = 200
sleep 1
check bypass-summary-mode-count grep -q 'site=demo;mode=count' <(tail -n 5 "$LOGS/audit.log")
"$W" bypass list | grep -q '^demo ' && pass bypass-list || fail bypass-list
"$W" bypass clear demo >/dev/null 2>&1
check bypass-clear-blocks test "$(demo -A '')" = 403

# 4. explain
check explain-tuned grep -Eq 'SizeRestrictions_BODY +block +count +site' <("$W" explain tuned)
finish
