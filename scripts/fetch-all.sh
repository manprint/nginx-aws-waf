#!/usr/bin/env bash
# Scarica tutte le risorse esterne del progetto.
set -uo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
"$D/fetch-aws-docs.sh"
"$D/fetch-ip-lists.sh"
"$D/fetch-crs.sh"
docker pull -q "${WAF_IMAGE:-owasp/modsecurity-crs:4.30.0-nginx-alpine-202611190211}"
# Richiede credenziali AWS (con MFA se imposto dalla policy): errore non bloccante.
"$D/fetch-aws-rulegroups.sh" || echo "WARN  fetch-aws-rulegroups saltato (credenziali/MFA)" >&2
