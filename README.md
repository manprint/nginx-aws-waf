# nginx_aws_waf

Simulatore della web ACL AWS WAF "one-click" per ALB (`AWSManagedRulesAmazonIpReputationList` →
`AWSManagedRulesCommonRuleSet` → `AWSManagedRulesKnownBadInputsRuleSet`) su nginx +
libmodsecurity v3 in Docker. Due usi:

1. **laboratorio di tuning** prima di andare su AWS: stesse regole, nomi, label e azioni di
   default; ogni regola può andare in Count come su AWS; ogni elemento di configurazione è
   marcato `aws-compatible` o `nginx-only`;
2. **WAF di produzione** per nodi EC2 con nginx senza ALB (circa 20 nodi), con log completi,
   statistiche, dashboard e inoltro mTLS verso un nodo centrale.

Il catalogo `waf/catalog/rules.yaml` è la fonte unica delle regole; `wafctl` (Go) valida la
configurazione, la renderizza in config nginx/ModSecurity, la applica e la testa.
I pattern AWS non pubblici sono approssimati (colonna `fidelity` del catalogo).

## Quickstart (lab)

```sh
source scripts/lab-env.sh   # WAF_HOME, WAF_CONFIG_DIR=lab/config, WAF_DATA_DIR=.run, PATH
make fetch                  # liste IP, documentazione AWS, sorgenti CRS
make lab-min-up             # build wafctl, liste, apply: nodo WAF + echo + vector (porta 8080)
make test-e2e               # corpus di richieste (tests/corpus), atteso "PASSED n/n"
tests/e2e/smoke.sh          # smoke test del nodo
wafctl explain tuned        # come è configurato un sito
make lab-min-down
```

## Lab Odoo

Quattro Odoo Community (12, 14, 16, 18) dietro il WAF, con Postgres dedicati. Serve circa
**10 GB di RAM libera**; il primo avvio crea i database (circa 3 minuti).

```sh
source scripts/lab-env.sh
make lab-up        # nodo + odoo12/14/16/18 su shopNN.lab.test (porta 8080), DB "lab", admin/admin
make lab-legit     # flussi Playwright legittimi: 0 blocchi attesi
make test-odoo     # corpus rilanciato sui siti Odoo con tests/odoo-exceptions.yaml
make lab-attack    # nuclei + nikto (risultati in build/lab/)
make lab-matrix    # matrice azioni/regole/disaccordi AWS → build/lab/matrix.md
make lab-down
```

Profili e motivazioni: [docs/odoo.md](docs/odoo.md).

## Mappa delle directory

| Percorso | Contenuto |
|---|---|
| `waf/` | catalogo regole, file dati, pagine 403/500, Dockerfile del motore |
| `wafctl/` | CLI Go (`validate`, `render`, `apply`, `diff`, `explain`, `bypass`, `test`, `logs`, `catalog`) |
| `profiles/` | profili di prodotto (`aws-default`, `shadow`, `strict`, `odoo-*`) |
| `lab/config/` | configurazione del nodo di lab (`node.yaml`, `sites/`) |
| `deploy/compose/` | compose del nodo (`node.yml` + `node.host.yml` / `node.bridge.yml`, lab) |
| `deploy/vector/` | pipeline Vector del nodo (eventi uniti in JSONL) |
| `deploy/systemd/` | timer per bypass e rotazione log |
| `tests/` | corpus di richieste, e2e, flussi legittimi Playwright (`tests/legit/`) |
| `scripts/` | fetch, `lab-env.sh`, `ngx-test.sh`, `bench.sh`, `lab-attack.sh`, `lab-matrix.sh` (+ `sql/`) |
| `data/` | liste IP e definizioni AWS scaricate |
| `docs/` | documentazione (sotto) e piani (`docs/plans/`) |

## Documentazione

- [docs/rules-spec.md](docs/rules-spec.md) — regole AWS e come sono riprodotte, schema ID
- [docs/config-reference.md](docs/config-reference.md) — tutte le chiavi di configurazione
- [docs/tuning.md](docs/tuning.md) — flusso shadow → count + label rule → enforce, bypass
- [docs/operations.md](docs/operations.md) — percorsi, apply/rollback, systemd, log
- [docs/performance.md](docs/performance.md) — benchmark
- [docs/odoo.md](docs/odoo.md) — profili Odoo, eccezioni, lab, tuning di un modulo
- [docs/lab-matrix-001.md](docs/lab-matrix-001.md) — matrice di lab finale del piano 001
- [tests/README.md](tests/README.md) — test e corpus
- [waf/README.md](waf/README.md) — motore e catalogo

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
