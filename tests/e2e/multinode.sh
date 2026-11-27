#!/usr/bin/env bash
# Multi-node over mTLS (P5). Part 1 (T-MN1): lab-node-2 (project waf2, data .run2, :18080) with a
# manually issued client cert forwards through the central ingress into ClickHouse.
# Part 2 (T-MN2..5): enroll with a one-time token via `wafctl pki serve`, token reuse refused,
# renew --force, revoke → the ingress refuses node 2.
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

# --- part 2: enrollment, renewal, revocation
serial_of() { "$W" pki list --format json | jq -r --arg s "$1" '.[] | select(.serial == $s) | .status'; }
cur_serial() { openssl x509 -in "$N2_DATA/certs/_node/node.pem" -noout -serial | cut -d= -f2 | tr A-F a-f; }
"$W" pki serve --addr 127.0.0.1:6001 > /tmp/mn-pki-serve.log 2>&1 &
SERVE=$!
trap 'kill $SERVE 2>/dev/null' EXIT
for ((t=0; t<20; t++)); do curl -sk https://127.0.0.1:6001/healthz | grep -q ok && break; sleep 0.5; done
rm -rf "$N2_DATA/certs/_node"
out=$("$W" pki token --cn lab-node-2 --ttl 1h)
tok=$(sed -n 's/^token=//p' <<<"$out"); fp=$(sed -n 's/^ca_sha256=//p' <<<"$out")
n2 node enroll --central 127.0.0.1:6001 --token "$tok" --ca-sha256 "$(printf '0%.0s' {1..64})" > /tmp/mn-pin.out 2>&1
check "MN2-enroll-wrong-pin-aborts" grep -q "fingerprint mismatch" /tmp/mn-pin.out
n2 node enroll --central 127.0.0.1:6001 --token "$tok" --ca-sha256 "$fp" > /tmp/mn-enroll.out 2>&1; rc=$?
check "MN2-enroll (rc=$rc)" test "$rc" = 0
check "MN2-node-key-0600" test "$(stat -c %a "$N2_DATA/certs/_node/node.key" 2>/dev/null)" = 600
s1=$(cur_serial)
check "MN2-pki-list-valid" test "$(serial_of "$s1")" = valid
tag="mn2-$(date +%s)"; send 10 "$tag"
c=$(wait_count "SELECT count() FROM waf.events WHERE node_id = 'lab-node-2' AND startsWith(path, '/mn/$tag')" 10 40)
check "T-MN2 enrolled node2 forwards ($c >= 10)" test "$c" -ge 10
n2 node enroll --central 127.0.0.1:6001 --token "$tok" --ca-sha256 "$fp" > /tmp/mn-reuse.out 2>&1
check "T-MN3 token reuse refused (403)" grep -q "HTTP 403" /tmp/mn-reuse.out
n2 node renew --central 127.0.0.1:6001 > /tmp/mn-renew0.out 2>&1
check "MN4-renew-skips-fresh" grep -q "nothing to do" /tmp/mn-renew0.out
n2 node renew --central 127.0.0.1:6001 --force > /tmp/mn-renew.out 2>&1; rc=$?
s2=$(cur_serial)
check "T-MN4 renew --force: new serial (rc=$rc)" test "$rc" = 0 -a "$s2" != "$s1" -a "$(serial_of "$s2")" = valid
check "T-MN4 old serial renewed" test "$(serial_of "$s1")" = renewed
tag="mn4-$(date +%s)"; send 10 "$tag"
c=$(wait_count "SELECT count() FROM waf.events WHERE node_id = 'lab-node-2' AND startsWith(path, '/mn/$tag')" 10 40)
check "T-MN4 traffic after renew ($c >= 10)" test "$c" -ge 10
"$W" pki revoke "$s2" > /tmp/mn-revoke.out 2>&1
check "MN5-revoke-reloads-ingress" grep -q "ingress reloaded" /tmp/mn-revoke.out
sleep 12   # worker_shutdown_timeout 10s: the old session is dropped, the reconnect hits the new CRL
tag="mn5-$(date +%s)"; send 20 "$tag"
sleep 20
c=$(chq "SELECT count() FROM waf.events WHERE node_id = 'lab-node-2' AND startsWith(path, '/mn/$tag')")
check "T-MN5 revoked node2 delivers nothing ($c = 0)" test "${c:-x}" = 0
docker logs --since 40s waf2-vector-1 2>&1 | grep -qiE "handshake|certificate|broken pipe|transport error|connection"
check "T-MN5 node2 vector logs the refusal" test $? = 0
docker logs --since 40s waf-ingress-1 2>&1 | grep -q "certificate revoked"
check "T-MN5 ingress logs certificate revoked" test $? = 0
# cleanup: fresh cert so the lab keeps working (the buffered mn5 events are then delivered)
out=$("$W" pki token --cn lab-node-2 --ttl 1h)
n2 node enroll --central 127.0.0.1:6001 --token "$(sed -n 's/^token=//p' <<<"$out")" --ca-sha256 "$(sed -n 's/^ca_sha256=//p' <<<"$out")" >/dev/null 2>&1
c=$(wait_count "SELECT count() FROM waf.events WHERE node_id = 'lab-node-2' AND startsWith(path, '/mn/$tag')" 20 60)
check "MN5-after-reenroll buffered events delivered ($c >= 20)" test "$c" -ge 20
check "MN-serve-log-has-enroll" grep -q "enroll cn=lab-node-2" /tmp/mn-pki-serve.log
finish
