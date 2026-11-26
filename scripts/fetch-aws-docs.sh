#!/usr/bin/env bash
# Scarica la documentazione AWS WAF di riferimento (formato markdown) in docs/aws/.
# Fonte: docs.aws.amazon.com espone la versione .md di ogni pagina HTML.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs/aws"
mkdir -p "$OUT"

WAF="https://docs.aws.amazon.com/waf/latest/developerguide"
ELB="https://docs.aws.amazon.com/elasticloadbalancing/latest/application"

# nome_file|url
PAGES=(
  # Rule group attivati dall'integrazione one-click ALB
  "managed-rules-baseline.md|$WAF/aws-managed-rule-groups-baseline.md"        # CommonRuleSet + KnownBadInputs (+ AdminProtection)
  "managed-rules-ip-reputation.md|$WAF/aws-managed-rule-groups-ip-rep.md"     # AmazonIpReputationList (+ AnonymousIpList)
  "managed-rules-use-case.md|$WAF/aws-managed-rule-groups-use-case.md"        # SQLi, Linux, Unix, ... (opzionali)
  "managed-rules-changelog.md|$WAF/aws-managed-rule-groups-changelog.md"
  "alb-waf-integration.md|$ELB/load-balancer-integrations.md"
  # Semantica del motore da emulare
  "rule-actions.md|$WAF/waf-rule-action.md"
  "block-response.md|$WAF/customizing-the-response-for-blocked-requests.md"
  "text-transformations.md|$WAF/waf-rule-statement-transformation.md"
  "oversize-components.md|$WAF/waf-oversize-request-components.md"
  "body-inspection-limit.md|$WAF/web-acl-setting-body-inspection-limit.md"
  "labels.md|$WAF/waf-labels.md"
  "rule-group-override.md|$WAF/web-acl-rule-group-override-options.md"
  "logging-fields.md|$WAF/logging-fields.md"
  "log-examples.md|$WAF/logging-examples.md"
)

fail=0
for entry in "${PAGES[@]}"; do
  name="${entry%%|*}"; url="${entry#*|}"
  if curl -fsSL --retry 2 "$url" -o "$OUT/$name.tmp"; then
    { echo "<!-- source: ${url%.md}.html | fetched: $(date -u +%F) -->"; cat "$OUT/$name.tmp"; } > "$OUT/$name"
    rm -f "$OUT/$name.tmp"
    printf 'ok    %-32s %6s B\n' "$name" "$(wc -c < "$OUT/$name")"
  else
    rm -f "$OUT/$name.tmp"
    printf 'FAIL  %-32s %s\n' "$name" "$url" >&2
    fail=1
  fi
done
exit $fail
