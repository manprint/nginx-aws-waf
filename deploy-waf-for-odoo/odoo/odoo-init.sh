#!/bin/bash
# Crea il database Odoo al primo avvio. Se esiste già non fa nulla.
set -euo pipefail
export PGPASSWORD=odoo
DB="${ODOO_DB:-odoo}"

if psql -h db -U odoo -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${DB}'" | grep -q 1; then
	echo "odoo-init: database '${DB}' già presente, niente da fare"
	exit 0
fi

demo=()
[[ ${ODOO_DEMO:-true} == true ]] || demo=(--without-demo=all)

echo "odoo-init: creo il database '${DB}' con i moduli ${ODOO_MODULES} (demo=${ODOO_DEMO:-true}); 2-4 minuti..."
odoo --db_host=db --db_user=odoo --db_password=odoo -d "$DB" \
	-i "base,${ODOO_MODULES}" "${demo[@]}" --stop-after-init --log-level=warn
echo "odoo-init: fatto. Login: admin / admin"
