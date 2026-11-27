#!/usr/bin/env bash
# V001-F1: a foreign CA's CRL never reaches the live ingress.
# 1. tests/e2e/pki.sh leaves the lab ingress crl.pem untouched.
# 2. A revoke in a throwaway WAF_PKI_DIR with the lab data dir is refused (rc != 0) and changes nothing.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
W="${WAFCTL:-$ROOT/wafctl/bin/wafctl}"
CRL="${WAF_CENTRAL_DIR:-${WAF_DATA_DIR:-$ROOT/.run}/central}/ingress/certs/crl.pem"
[ -s "$CRL" ] || { echo "FAIL PKI-ISO-precondition (no ingress crl.pem at $CRL: run the lab first)"; exit 1; }
sum0=$(md5sum < "$CRL")
"$(dirname "$0")/pki.sh" >/dev/null 2>&1
check "PKI-ISO-pki.sh-ALL-PASS" test $? = 0
check "PKI-ISO-crl-unchanged" test "$(md5sum < "$CRL")" = "$sum0"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
(
  export WAF_PKI_DIR="$T/pki"
  "$W" pki init --name foreign >/dev/null && "$W" pki issue --cn x --kind client --out "$T/x" >/dev/null || exit 9
  "$W" pki revoke x > "$T/out" 2>&1
)
rc=$?
check "PKI-ISO-foreign-crl-refused (rc=$rc)" bash -c "[ $rc -ne 0 ] && [ $rc -ne 9 ] && grep -q 'not the ingress CA' '$T/out'"
check "PKI-ISO-crl-still-unchanged" test "$(md5sum < "$CRL")" = "$sum0"
finish
