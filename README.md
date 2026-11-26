# nginx_aws_waf

Simulazione locale di AWS WAF davanti a un ALB, con la web ACL di default dell'integrazione
one-click ALB:

- `AWSManagedRulesAmazonIpReputationList`
- `AWSManagedRulesCommonRuleSet`
- `AWSManagedRulesKnownBadInputsRuleSet`

Motore: nginx + libmodsecurity v3 (immagine `owasp/modsecurity-crs`), regole custom che
riproducono nomi, label e azioni delle regole AWS. Pattern AWS non pubblici → comportamento approssimato.

## Risorse esterne

```sh
./scripts/fetch-all.sh
```

| Script | Output | Versionato |
|---|---|---|
| `fetch-aws-docs.sh` | `docs/aws/*.md` – documentazione AWS WAF di riferimento | sì |
| `fetch-ip-lists.sh` | `data/ip-reputation/*.txt` – feed open che approssimano le liste IP AWS | no (tranne `custom-test.txt`) |
| `fetch-crs.sh` | `vendor/coreruleset` – sorgente OWASP CRS 4.30.0 | no |
| `fetch-aws-rulegroups.sh` | `data/aws-managed-rules/*.json` – definizione ufficiale via `wafv2 describe-managed-rule-group` | sì |
| (docker) | `owasp/modsecurity-crs:4.30.0-nginx-alpine-202611190211` | – |
