# Export verso AWS WAF

`wafctl export-aws` traduce la configurazione effettiva di un sito (default ← profili ← sito)
in una web ACL AWS WAFv2 (scope `REGIONAL`, da associare a un ALB). L'export può essere:

- JSON: l'input di `CreateWebACL`, più gli input di `CreateIPSet`;
- un modulo Terraform.

Gli elementi `nginx-only` non hanno un equivalente AWS. Per esportarli serve `--allow-lossy`;
vengono omessi ed elencati nel campo `lossy`.

```bash
wafctl export-aws --site shop18                                   # JSON su stdout; exit 2 se il sito non è aws-compatible
wafctl export-aws --site shop18 --allow-lossy -o build/aws/shop18.json
wafctl export-aws --site shop18 --allow-lossy --acl-only -o build/aws/shop18-acl.json   # solo CreateWebACL
wafctl export-aws --site shop18 --format terraform --allow-lossy -o build/aws/shop18.tf
wafctl export-aws --site shop18 --region eu-south-1 --account 123456789012 ...         # ARN degli IP set
```

Senza `--allow-lossy`, un sito non compatibile esce con codice 2 ed elenca i motivi:

```
wafctl: site tuned is not aws-compatible:
  - client_ip.source=xff
  - path_overrides
use --allow-lossy to export without these features
```

## Documento JSON

```json
{"web_acl": {...}, "ip_sets": [{...}], "manual_steps": ["..."], "lossy": ["..."]}
```

- `web_acl` è l'input di `aws wafv2 create-web-acl --cli-input-json`.
- `ip_sets` contiene un input di `aws wafv2 create-ip-set` per ogni IP set.
- `manual_steps` sono i passi da fare a mano (sotto).
- `lossy` elenca le funzioni omesse.

## Ordine e priorità delle regole

La priorità parte da 0 e cresce di 10 per ogni regola. L'ordine è lo stesso del motore nginx:

1. la regola rate-based `RateLimit` (`rate_limit`), se c'è;
2. le custom rule con `slot: start`, con `GeoBlock` (`geo_block`) per prima;
3. per ogni rule group gestito attivo, nell'ordine del catalogo (IpReputation → AnonymousIp →
   CommonRuleSet → KnownBadInputs → SQLi): prima il gruppo (`AWS-<NomeGruppo>`), poi le sue custom
   rule `slot: after:<NomeGruppo>`.

Esempio per il sito `tuned` del lab:

| Priorità | Regola |
|---|---|
| 0 | `AWS-AWSManagedRulesAmazonIpReputationList` |
| 10 | `AWS-AWSManagedRulesCommonRuleSet` (override `SizeRestrictions_BODY` → Count) |
| 20 | `BlockLargeBodyOutsideRpc` (label `SizeRestrictions_Body` AND NOT path `/web/dataset/`) |
| 30 | `AWS-AWSManagedRulesKnownBadInputsRuleSet` |

## Mappatura

| Configurazione | AWS WAF |
|---|---|
| `default_action: allow/block` | `DefaultAction {Allow}` / `{Block}` |
| rule group attivo | `ManagedRuleGroupStatement {VendorName: AWS, Name}` con `OverrideAction {None}` |
| `override_action: count` del gruppo | `OverrideAction {Count}` |
| `rule_action_overrides: {Regola: azione}` | `RuleActionOverrides [{Name, ActionToUse}]`, solo se l'azione è diversa dal default del catalogo |
| `scope_down` | `ScopeDownStatement` |
| `mode: count` (profilo `shadow`, bypass) | tutti i gruppi `OverrideAction {Count}`, tutte le custom/rate `Action {Count}` |
| custom rule `action: block/allow/count` | `Action {Block}` / `{Allow}` / `{Count}` |
| `match.all` con una condizione | lo statement stesso |
| `match.all` con più condizioni | `AndStatement` |
| `negate: true` | `NotStatement` |
| `label` / `label_namespace` | `LabelMatchStatement` con `Scope: LABEL` / `NAMESPACE` |
| `uri_path` / `header` / `query_arg` con `exact`, `starts_with`, `contains` | `ByteMatchStatement` con `PositionalConstraint` `EXACTLY` / `STARTS_WITH` / `CONTAINS` su `UriPath` / `SingleHeader` (nome minuscolo) / `SingleQueryArgument` |
| `... regex` | `RegexMatchStatement` |
| `transform: [urlDecodeUni, lowercase]` | `TextTransformations` `URL_DECODE_UNI`, `LOWERCASE` (nessuna → `NONE`) |
| `method: [PUT, DELETE]` | un `ByteMatchStatement` `EXACTLY` su `Method` per metodo; più di uno → `OrStatement` |
| `ip_set: [...]` | IP set `waf-<sito>-<regola>-v4` / `-v6` + `IPSetReferenceStatement`; se ci sono sia v4 sia v6 → `OrStatement` |
| `geo: [...]`, `geo_block` | `GeoMatchStatement {CountryCodes}` |
| `size` | `SizeConstraintStatement` (`body` → `Body` con `OversizeHandling: CONTINUE`, `cookie` → `Cookies` tutti) |
| `rate_limit {limit, window_sec, action}` | `RateBasedStatement {Limit, EvaluationWindowSec, AggregateKeyType: IP}` |
| `body_limit` tra 8192 e 65536 (valori AWS) | passo manuale sull'ALB |

`VisibilityConfig` è sempre attivo: metriche CloudWatch e richieste campionate. Il `MetricName` è
il nome della regola, con i caratteri fuori da `[A-Za-z0-9_-]` sostituiti da `_`.

## Funzioni non esportabili (`lossy`)

| Motivo | Cosa succede su AWS |
|---|---|
| `client_ip.source=xff` | AWS usa l'IP sorgente della connessione all'ALB. Nel lab è un artefatto del test (gli IP dei client sono simulati con `X-Forwarded-For`) |
| `path_overrides` | non esiste un'azione per regola limitata a un path. Usa `rule_action_overrides` + `scope_down` o una label rule |
| `body_limit` fuori da {8192, 16384, 32768, 49152, 65536} | l'ALB ispeziona al massimo 64 KB |
| `fail.pcre_limit=block`, `fail.body_error=closed/block` | AWS non ha questi fallimenti configurabili |
| `audit.scope=relevant` | i log AWS non hanno un audit con i corpi |
| `block_page` diverso da `aws` | su AWS la risposta 403 si personalizza con le custom response (non esportate) |
| `shadow mode with default_action block` | in Count una web ACL con default Block bloccherebbe comunque tutto |

`wafctl validate` segnala gli stessi motivi come avvisi `nginx-only`.

## Passi manuali (`manual_steps`)

- **Associazione all'ALB.** Nel JSON va fatta a mano. Nel Terraform basta impostare
  `alb_arn` (sotto).
- **IP set.** Solo nel JSON: crea prima gli IP set con `create-ip-set`, poi sostituisci gli ARN
  segnaposto (`.../ipset/<nome>/00000000-...`) nella web ACL con quelli restituiti. Nel Terraform
  gli ARN sono riferimenti `aws_wafv2_ip_set.<nome>.arn` e il passo non serve.
- **Body inspection.** Se `body_limit` è diverso da 8192, imposta il limite di ispezione del body
  sull'ALB (attributi del load balancer, integrazione WAF).

## Validazione offline

Nessuno dei due controlli contatta AWS e nessuno dei due crea risorse.

```bash
make aws-export-check                                     # tutti i siti del lab: JSON + validazione AWS CLI
scripts/aws-validate-acl.sh build/aws/shop18-acl.json     # VALID / INVALID (exit 1)
jq '.ip_sets[0]' build/aws/x.json > /tmp/ip.json && scripts/aws-validate-acl.sh --ip-set /tmp/ip.json
scripts/tf-validate-export.sh build/aws/shop18.tf         # terraform init -backend=false + validate + fmt -check
```

- `aws-validate-acl.sh` usa la validazione dei parametri della AWS CLI. La richiesta viene
  costruita e controllata localmente, poi inviata a un endpoint irraggiungibile. "Could not
  connect" significa input valido. Senza `aws` installato usa l'immagine `amazon/aws-cli:2.35.21`.
- `tf-validate-export.sh` usa l'immagine `hashicorp/terraform:1.17.2`, la stessa di
  `make tf-validate`. I provider sono in cache in `build/.tf-plugin-cache`.

## Applicare con Terraform (manuale)

L'applicazione su AWS non è automatizzata. Va fatta dall'operatore con le proprie credenziali.

```bash
mkdir -p ~/waf-aws/shop18 && cp build/aws/shop18.tf ~/waf-aws/shop18/main.tf
cd ~/waf-aws/shop18
terraform init
terraform plan -var alb_arn=arn:aws:elasticloadbalancing:eu-central-1:123456789012:loadbalancer/app/shop/abc
terraform apply -var alb_arn=...
```

Il modulo contiene:

- il provider `hashicorp/aws ~> 6.0` con la regione di `--region`;
- gli `aws_wafv2_ip_set`;
- la `aws_wafv2_web_acl`;
- una `aws_wafv2_web_acl_association`, creata solo se `alb_arn` non è vuoto.

I passi manuali e le funzioni `lossy` sono in commento in testa al file. Non modificare il file
generato: cambia la configurazione e riesporta.

Prima di passare in Block, conviene esportare il sito in `mode: count` (profilo `shadow`). Così
tutta la web ACL è in Count e puoi confrontare le metriche CloudWatch con le statistiche del lab
(`wafctl stats --by rule`).
