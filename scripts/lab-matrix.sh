#!/usr/bin/env bash
# Lab matrix over one day of raw logs with clickhouse local (no server needed).
# Usage: scripts/lab-matrix.sh [--date YYYY-MM-DD] [--out build/lab/matrix.md] [--sql matrix.sql|legit.sql]
# With --sql legit.sql the count is printed on stdout (gate: must be 0) and --out is ignored.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATE="$(date -u +%F)"; OUT="$ROOT/build/lab/matrix.md"; SQL=matrix.sql
while (($#)); do
  case "$1" in
    --date) DATE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --sql) SQL="$(basename "$2")"; shift 2 ;;
    *) echo "usage: $0 [--date YYYY-MM-DD] [--out FILE] [--sql matrix.sql|legit.sql]" >&2; exit 2 ;;
  esac
done
RAW="${WAF_DATA_DIR:-$ROOT/.run}/raw"
RAW="$(cd "$RAW" && pwd)"
[[ -f "$RAW/$DATE/events.jsonl" ]] || { echo "lab-matrix: no $RAW/$DATE/events.jsonl" >&2; exit 1; }
touch "$RAW/$DATE/matches.jsonl" 2>/dev/null || true
run() {
  docker run --rm -v "$RAW:/raw:ro" -v "$ROOT/scripts/sql:/sql:ro" \
    clickhouse/clickhouse-server:26.8-alpine clickhouse local --param_d="$DATE" --queries-file "/sql/$SQL"
}
if [[ "$SQL" == matrix.sql ]]; then
  mkdir -p "$(dirname "$OUT")"
  { echo "# WAF lab matrix — $DATE (UTC)"; echo; run; } > "$OUT"
  echo "lab-matrix: wrote $OUT"
else
  run
fi
