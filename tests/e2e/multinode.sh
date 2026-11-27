#!/usr/bin/env bash
# Multi-node over mTLS (P5). Part 1 (T-MN1): lab-node-2 (project waf2, data .run2, :18080) with a
# manually issued client cert forwards through the central ingress into ClickHouse.
# Usage: tests/e2e/multinode.sh [part1]
set -uo pipefail
source "$(dirname "$0")/lib.sh"
PART="${1:-all}"
W="${WAFCTL:-$ROOT/wafctl/bin/wafctl}"
C1="${WAF_CONFIG_DIR:-$ROOT/lab/config}"
export WAF_PKI_DIR="${WAF_PKI_DIR:-$C1/pki}"
source "$C1/secrets.env"
N2_DATA="$ROOT/.run2"
n2() { WAF_CONFIG_DIR="$ROOT/lab/config-node2" WAF_DATA_DIR="$N2_DATA" WAF_COMPOSE_PROJECT=waf2 \
  WAF_COMPOSE_EXTRA=deploy/compose/lab-min.yml:deploy/compose/lab-node2.yml "$W" "$@"; }
chq() { curl -s -u "waf_admin:$WAF_CH_ADMIN_PASSWORD" http://127.0.0.1:8123/ --data-binary "$1"; }
N2_URL=http://127.0.0.1:18080
send() { # send <n> <tag>: n requests to node 2, demo site
  for ((i=0; i<$1; i++)); do curl -s -o /dev/null -H 'Host: demo.lab.test' -H "X-Waf-Test: $2-$i" "$N2_URL/mn/$2"; done; }
wait_count() { # wait_count <sql> <min> <secs> → prints the last count
  local c=0
  for ((t=0; t<$3; t++)); do c=$(chq "$1"); (( ${c:-0} >= $2 )) && break; sleep 1; done; echo "${c:-0}"; }

# --- part 1: manual client cert, TLS forward, ingest
mkdir -p "$N2_DATA"/{runtime,logs,certs/_node,geoip,raw,vector,lists}
chmod 700 "$N2_DATA/certs/_node"
cp "${WAF_DATA_DIR:-$ROOT/.run}"/lists/*.txt "$N2_DATA/lists/"
if ! [ -s "$N2_DATA/certs/_node/node.pem" ] || [ "$PART" = part1 ]; then
  "$W" pki issue --cn lab-node-2 --kind client --out "$N2_DATA/certs/_node" >/dev/null
  mv "$N2_DATA/certs/_node/lab-node-2.pem" "$N2_DATA/certs/_node/node.pem"
  mv "$N2_DATA/certs/_node/lab-node-2.key" "$N2_DATA/certs/_node/node.key"
fi
n2 apply > /tmp/mn-apply.out 2>&1; rc=$?
check "MN1-apply-node2 (rc=$rc)" test "$rc" = 0
(( rc != 0 )) && tail -5 /tmp/mn-apply.out
for ((t=0; t<30; t++)); do curl -s -o /dev/null -H 'Host: demo.lab.test' "$N2_URL/" && break; sleep 1; done
grep -q 'tls: {enabled: true' "$N2_DATA/runtime/current/vector/forward.yaml"
check "MN1-forward-tls-rendered" test $? = 0
tag="mn1-$(date +%s)"
send 20 "$tag"
c=$(wait_count "SELECT count() FROM waf.events WHERE node_id = 'lab-node-2' AND startsWith(path, '/mn/$tag')" 20 30)
check "T-MN1 node2 events via mTLS ingress ($c >= 20)" test "$c" -ge 20
# handshake probes (the stream access log is written when a session ends; Vector's is long-lived)
D="$N2_DATA/certs/_node"
probe() { echo | timeout 5 openssl s_client -connect 127.0.0.1:6000 -servername central.lab.test -alpn h2 \
  -CAfile "$D/ca.pem" -verify_return_error "$@" >/dev/null 2>&1; sleep 1; docker logs --tail 1 waf-ingress-1 2>&1; }
check "MN1-ingress-rejects-no-cert" bash -c "$(declare -f probe); D='$D'; probe | grep -q '\"-\" NONE 500'"
check "MN1-ingress-accepts-node-cert" bash -c "$(declare -f probe); D='$D'; probe -cert '$D/node.pem' -key '$D/node.key' | grep -q 'CN=lab-node-2\" SUCCESS 200'"
[[ "$PART" == part1 ]] && { finish; exit 0; }
finish
