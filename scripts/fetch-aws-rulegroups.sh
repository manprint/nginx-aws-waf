#!/usr/bin/env bash
# Scarica la definizione ufficiale (nomi regole, azioni, label, WCU, versione) dei managed rule group AWS
# via API (chiamate read-only, gratuite). Richiede credenziali AWS con wafv2:DescribeManagedRuleGroup.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/data/aws-managed-rules"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || echo eu-west-1)}}"
mkdir -p "$OUT"

GROUPS=(
  AWSManagedRulesAmazonIpReputationList   # default ALB
  AWSManagedRulesCommonRuleSet            # default ALB
  AWSManagedRulesKnownBadInputsRuleSet    # default ALB
  AWSManagedRulesSQLiRuleSet              # opzionale
  AWSManagedRulesAnonymousIpList          # opzionale
  AWSManagedRulesAdminProtectionRuleSet   # opzionale
)

for g in "${GROUPS[@]}"; do
  aws wafv2 describe-managed-rule-group --region "$REGION" --scope REGIONAL \
      --vendor-name AWS --name "$g" --output json > "$OUT/$g.json"
  aws wafv2 list-available-managed-rule-group-versions --region "$REGION" --scope REGIONAL \
      --vendor-name AWS --name "$g" --output json > "$OUT/$g.versions.json"
  printf 'ok    %-40s %3s regole  WCU=%s  default=%s\n' "$g" \
    "$(jq '.Rules | length' "$OUT/$g.json")" "$(jq -r .Capacity "$OUT/$g.json")" \
    "$(jq -r '.CurrentDefaultVersion // "-"' "$OUT/$g.versions.json")"
done
