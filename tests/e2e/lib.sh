# shared helpers for tests/e2e/*.sh (source it)
FAILS=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1${2:+ — $2}"; FAILS=$((FAILS+1)); }
check() { local id="$1"; shift; if "$@"; then pass "$id"; else fail "$id"; fi; }
finish() { if (( FAILS > 0 )); then echo "FAILED $FAILS check(s)"; exit 1; fi; echo "ALL PASS"; }
WAF_URL="${WAF_URL:-http://127.0.0.1:8080}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGS="${WAF_DATA_DIR:-$ROOT/.run}/logs"
