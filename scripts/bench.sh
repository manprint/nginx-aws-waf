#!/usr/bin/env bash
# G-PERF: D29 throughput/latency check of a WAF node with oha.
# Usage: scripts/bench.sh [--target http://127.0.0.1:8080] [--host demo.lab.test]
# Prints CSV: date,commit,case,rps,p50_ms,p99_ms,waf_rss_mb ; exit 1 if a D29 threshold fails, 3 if oha is missing.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET=http://127.0.0.1:8080; HOST=demo.lab.test
while (( $# )); do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --host) HOST="$2"; shift 2;;
    *) echo "usage: $0 [--target URL] [--host NAME]" >&2; exit 2;;
  esac
done
OHA="$(command -v oha || true)"; [[ -z "$OHA" && -x "$HOME/.cargo/bin/oha" ]] && OHA="$HOME/.cargo/bin/oha"
[[ -z "$OHA" ]] && { echo "oha not found" >&2; exit 3; }
CONTAINER="${WAF_CONTAINER:-waf-waf-1}"
commit=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo none)
rc=0
echo "date,commit,case,rps,p50_ms,p99_ms,waf_rss_mb"
run() { # case min_rps max_p99 oha-args...
  local name="$1" min="$2" maxp="$3"; shift 3
  local out rps p50 p99 rss
  out=$("$OHA" -z 10s -c 8 --no-tui -H "Host: $HOST" "$@" 2>&1)
  rps=$(awk '/Requests\/sec:/ {printf "%.0f", $2}' <<<"$out")
  p50=$(awk '/50.00% in/ {print $3}' <<<"$out")
  p99=$(awk '/99.00% in/ {print $3}' <<<"$out")
  rss=$(docker stats --no-stream --format '{{.MemUsage}}' "$CONTAINER" 2>/dev/null | awk '{v=$1; u=v; gsub(/[0-9.]/,"",u); gsub(/[^0-9.]/,"",v); if(u=="GiB")v*=1024; if(u=="KiB")v/=1024; printf "%.1f", v}')
  echo "$(date -u +%FT%TZ),$commit,$name,${rps:-0},${p50:-NA},${p99:-NA},${rss:-NA}"
  if [[ -z "$rps" || -z "$p99" ]] || (( rps < min )) || awk -v p="$p99" -v m="$maxp" 'BEGIN{exit !(p>m)}'; then
    echo "FAIL $name: need rps >= $min and p99 <= $maxp ms" >&2; rc=1
  fi
}
run get 3500 5 "$TARGET/web/login?redirect=%2Fweb"
run post 3000 5 -m POST -T application/json -D "$ROOT/tests/bench/rpc.json" "$TARGET/web/dataset/call_kw"
exit $rc
