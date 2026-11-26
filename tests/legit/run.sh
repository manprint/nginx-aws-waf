#!/usr/bin/env bash
# Run the Playwright legit flows inside the waf_lab network.
# Usage: tests/legit/run.sh shop12,shop14,shop16,shop18   (last line: RUN_ID=<id>)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export SITES="${1:-shop12,shop14,shop16,shop18}"
export RUN_ID="${RUN_ID:-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
docker compose -p waf -f "$ROOT/deploy/compose/lab-tools.yml" --profile tools run --rm -e SITES -e RUN_ID playwright
rc=$?
echo "RUN_ID=$RUN_ID"
exit $rc
