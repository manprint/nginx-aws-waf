#!/usr/bin/env bash
# Attack generators (nuclei, nikto) against the Odoo lab sites, sequentially, through the WAF.
# Usage: scripts/lab-attack.sh shop12,shop14,shop16,shop18   (last line: RUN_ID=<id>)
# Output: build/lab/nuclei-<site>.jsonl, build/lab/nikto-<site>.txt
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SITES="${1:-shop12,shop14,shop16,shop18}"
RUN_ID="${RUN_ID:-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export COMPOSE_IGNORE_ORPHANS=True   # lab services live in other compose files of project waf
DC=(docker compose -p waf -f "$ROOT/deploy/compose/lab-tools.yml" --profile tools)
mkdir -p "$ROOT/build/lab"
"${DC[@]}" build -q nikto || exit 1
rc=0
for s in ${SITES//,/ }; do
  echo "== $s nuclei"
  "${DC[@]}" run --rm nuclei -u http://waf:8080 -H "Host: $s.lab.test" -H "X-Waf-Test: $RUN_ID-nuclei" \
    -tags cve,lfi,xss,sqli,rce,exposure -severity medium,high,critical -rl 50 -silent -jsonl \
    -o "/out/nuclei-$s.jsonl" >/dev/null || rc=1
  echo "== $s nikto"
  "${DC[@]}" run --rm nikto -h http://waf:8080 -vhost "$s.lab.test" -useragent "Mozilla/5.0 nikto-lab $RUN_ID-nikto" \
    -Tuning 123489b -maxtime 600s -o "/out/nikto-$s.txt" >/dev/null || true   # nikto exits non-zero when it finds items
done
echo "RUN_ID=$RUN_ID"
exit $rc
