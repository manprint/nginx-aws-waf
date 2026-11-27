#!/usr/bin/env bash
# PKI core (5.1) with openssl as the independent verifier, in a throwaway $WAF_PKI_DIR.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
W="${WAFCTL:-$ROOT/wafctl/bin/wafctl}"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export WAF_PKI_DIR="$T/pki"
fp=$("$W" pki init --name e2e | sed -n 's/^ca_sha256=//p')
check "PKI-init-fingerprint-matches-openssl" test "$fp" = "$(openssl x509 -in "$T/pki/ca.pem" -outform der | sha256sum | cut -d' ' -f1)"
check "PKI-init-twice-refused" bash -c "! '$W' pki init --name e2e 2>/dev/null"
check "PKI-ca-key-0600" test "$(stat -c %a "$T/pki/private/ca.key")" = 600
check "PKI-ca-is-ca" bash -c "openssl x509 -in '$T/pki/ca.pem' -noout -ext basicConstraints | grep -q 'CA:TRUE, pathlen:0'"
"$W" pki issue --cn lab-node-2 --kind client --out "$T/n" >/dev/null
"$W" pki issue --cn ingress --kind server --dns ingress --out "$T/s" >/dev/null
check "PKI-openssl-verify-client" openssl verify -CAfile "$T/pki/ca.pem" -purpose sslclient "$T/n/lab-node-2.pem"
check "PKI-client-not-server" bash -c "! openssl verify -CAfile '$T/pki/ca.pem' -purpose sslserver '$T/n/lab-node-2.pem' >/dev/null 2>&1"
check "PKI-openssl-verify-server" openssl verify -CAfile "$T/pki/ca.pem" -purpose sslserver "$T/s/ingress.pem"
check "PKI-leaf-key-0600" test "$(stat -c %a "$T/n/lab-node-2.key")" = 600
check "PKI-leaf-p256" bash -c "openssl x509 -in '$T/n/lab-node-2.pem' -noout -text | grep -q 'NIST CURVE: P-256'"
serial=$("$W" pki list --format json | jq -r '.[] | select(.cn == "lab-node-2") | .serial')
"$W" pki revoke lab-node-2 >/dev/null
check "PKI-crl-lists-revoked" bash -c "openssl crl -in '$T/pki/crl.pem' -noout -text | grep -qi 'Serial Number: $serial'"
check "PKI-crl-verify-revoked" bash -c "openssl verify -crl_check -CRLfile '$T/pki/crl.pem' -CAfile '$T/pki/ca.pem' '$T/n/lab-node-2.pem' 2>&1 | grep -q 'certificate revoked'"
check "PKI-crl-server-still-ok" openssl verify -crl_check -CRLfile "$T/pki/crl.pem" -CAfile "$T/pki/ca.pem" "$T/s/ingress.pem"
check "PKI-list-status-revoked" bash -c "'$W' pki list | grep -E '^$serial +lab-node-2 +client .* revoked$' >/dev/null"
tok=$("$W" pki token --cn lab-node-3 --ttl 1h | sed -n 's/^token=//p')
check "PKI-token-not-stored-in-clear" bash -c "! grep -q '$tok' '$T/pki/tokens.json'"
finish
