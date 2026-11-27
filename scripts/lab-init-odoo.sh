#!/usr/bin/env bash
# Create the "lab" database of each Odoo version (once) and start the Odoo services.
# Usage: scripts/lab-init-odoo.sh [12 14 16 18]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export WAF_DATA_DIR="${WAF_DATA_DIR:-$ROOT/.run}"
DC=(docker compose -p waf --env-file "${WAF_CONFIG_DIR:-lab/config}/secrets.env" -f deploy/compose/node.yml -f deploy/compose/node.bridge.yml -f deploy/compose/central.yml -f deploy/compose/central.bridge.yml -f deploy/compose/lab-min.yml -f deploy/compose/lab.yml)
declare -A PG=([12]=pg12 [14]=pg13 [16]=pg15 [18]=pg16)
MODULES=contacts,crm,sale_management,website_sale,website_crm
versions=("$@"); (( ${#versions[@]} )) || versions=(12 14 16 18)
for v in "${versions[@]}"; do
  pg=${PG[$v]:?unknown version $v}
  "${DC[@]}" up -d "$pg" >/dev/null
  for _ in $(seq 60); do "${DC[@]}" exec -T "$pg" pg_isready -U odoo -q && break; sleep 1; done
  if "${DC[@]}" exec -T "$pg" psql -U odoo -lqt | cut -d'|' -f1 | grep -qw lab; then
    echo "odoo$v: database lab exists"
  else
    echo "odoo$v: initialising database lab ($MODULES)"
    t0=$(date +%s)
    "${DC[@]}" run --rm --no-deps odoo$v odoo --db_host=$pg --db_user=odoo --db_password=odoo -d lab \
      -i $MODULES --without-demo=all --stop-after-init
    echo "odoo$v: init took $(( $(date +%s) - t0 )) s"
  fi
  "${DC[@]}" up -d odoo$v >/dev/null
done
for v in "${versions[@]}"; do
  ok=0
  for _ in $(seq 300); do
    c=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: shop$v.lab.test" http://127.0.0.1:8080/web/login || true)
    [[ "$c" == 200 ]] && { ok=1; break; }
    sleep 1
  done
  (( ok )) || { echo "odoo$v: /web/login not 200 after 300 s (last $c)" >&2; exit 1; }
  echo "odoo$v: ready"
done
