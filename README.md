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

## Osservabilità

`make lab-min-up` avvia anche lo storage centrale: ClickHouse su `127.0.0.1:8123` e
`vector-central`. Gli eventi di ogni richiesta arrivano lì in pochi secondi, arricchiti con
paese e ASN.

```sh
wafctl logs search --since 15m --action BLOCK          # ultime richieste bloccate
wafctl logs show <request_id>                          # evento completo + regole matchate
wafctl logs tail --site demo                           # in diretta
wafctl stats --since 24h --by rule --counted           # regole in COUNT che bloccherebbero
wafctl logs export --since 1h --format aws -o out.jsonl   # formato log AWS WAF
wafctl report --html --since 24h -o build/report.html  # report autocontenuto
wafctl stats --since 1h --raw .run/raw                 # offline, senza ClickHouse
```

Dettagli (flusso, tabelle, campi, mappatura AWS, retention, GeoIP):
[docs/observability.md](docs/observability.md).

### Dashboard e alert

Il centrale ha anche Prometheus (metriche di nginx, host e Vector per nodo), Grafana su
`127.0.0.1:3000` con 4 dashboard (Overview, Rules & Tuning, Request Explorer, Nodes Health) e
5 alert. Gli alert sono notificati tramite apprise a Slack, Google Chat, Telegram, ecc.

```sh
ssh -N -L 3000:127.0.0.1:3000 utente@centrale        # accesso da remoto (o Tailscale: grafana.bind)
grep GF_ADMIN_PASSWORD lab/config/secrets.env         # password di admin
wafctl grafana user add mario --role Viewer           # utente in sola lettura, password stampata una volta
echo 'slack://TokenA/TokenB/TokenC/#waf' >> $WAF_CONFIG_DIR/apprise-urls.txt && wafctl apply
```

Soglie in `$WAF_CONFIG_DIR/central.yaml`; pannelli, alert e apprise:
[docs/dashboards-alerts.md](docs/dashboards-alerts.md).

## Multi-nodo

I nodi inviano eventi e metriche al centrale via **mTLS** (porta 6000, nginx stream con CRL).
I certificati sono emessi da una CA propria. L'enrollment usa un token monouso, il rinnovo è
automatico e la revoca è immediata.

```sh
make release VERSION=0.5.0                                  # tarball per i server
# sul nodo (root): install-node.sh, poi
wafctl node bootstrap --node-id web-7 --role node --central central.example.com --install-systemd
# sul centrale
wafctl pki init --name prod && wafctl pki token --cn web-7  # stampa token e ca_sha256
# sul nodo
wafctl node enroll --token <T> --ca-sha256 <H>
```

Topologia, porte, PKI, revoca, scadenza della CRL, backup della CA, Tailscale e Terraform:
[docs/multi-node.md](docs/multi-node.md).

## Export verso AWS

Un sito configurato nel lab diventa una web ACL AWS WAFv2, in JSON (input della AWS CLI) o in
Terraform. Gli elementi `nginx-only` sono elencati come `lossy` e omessi (`--allow-lossy`).

```sh
wafctl export-aws --site shop18 --format terraform --allow-lossy -o build/aws/shop18.tf
scripts/tf-validate-export.sh build/aws/shop18.tf      # terraform validate in Docker → VALID
make aws-export-check                                  # tutti i siti: JSON + validazione offline AWS CLI
```

Mappatura, passi manuali e applicazione: [docs/aws-export.md](docs/aws-export.md).

## Liste IP e GeoIP

```sh
wafctl lists update        # aggiorna le liste di reputazione (protezione 50 %), apply se cambiate
```

Il timer `wafctl-lists` lo esegue ogni giorno. `wafctl-geoip` aggiorna GeoLite2 se c'è un account
MaxMind. Dettagli in [docs/operations.md](docs/operations.md#liste-ip).

## Accettazione finale

```sh
make final-check           # G-FINAL: lab-up, corpus, Playwright, ClickHouse ≤ 10 s, report,
                           # export log AWS, bypass, alert, export Terraform → "G-FINAL step N OK" × 8
scripts/bench.sh           # G-PERF (docs/performance.md)
```

Novità per versione: [CHANGELOG.md](CHANGELOG.md).

## Mappa delle directory

| Percorso | Contenuto |
|---|---|
| `waf/` | catalogo regole, file dati, pagine 403/500, Dockerfile del motore |
| `wafctl/` | CLI Go (`validate`, `render`, `apply`, `diff`, `explain`, `bypass`, `test`, `logs`, `stats`, `report`, `ch`, `secrets`, `central`, `grafana`, `pki`, `node`, `export-aws`, `lists`, `catalog`) |
| `profiles/` | profili di prodotto (`aws-default`, `shadow`, `strict`, `odoo-*`) |
| `lab/config/` | configurazione del nodo di lab (`node.yaml`, `sites/`); `lab/config-node2/` è il secondo nodo del lab multi-nodo |
| `deploy/compose/` | compose del nodo (`node.yml` + `node.host.yml` / `node.bridge.yml`), del centrale (`central.yml` con l'ingress mTLS, `central.bridge.yml`, `central.host.yml`), lab |
| `deploy/clickhouse/` | schema iniziale, utenti, config di ClickHouse |
| `deploy/grafana/` | tabella dei pannelli (`panels.py`) e dashboard JSON generate (`make dashboards`) |
| `deploy/vector/` | pipeline Vector del nodo (eventi uniti in JSONL, inoltro) e del centrale (GeoIP → ClickHouse) |
| `deploy/systemd/` | timer per bypass, rotazione log, CRL, rinnovo dei certificati, liste IP e GeoIP; servizio `wafctl-pki` |
| `deploy/terraform/` | scheletro Terraform AWS (security group, istanze, user-data), solo `make tf-validate` |
| `tests/` | corpus di richieste, e2e, flussi legittimi Playwright (`tests/legit/`) |
| `scripts/` | fetch, `lab-env.sh`, `ngx-test.sh`, `bench.sh`, `lab-attack.sh`, `lab-matrix.sh` (+ `sql/`), `gen-dashboards.py`, `check-dashboards.sh`, `build-release.sh`, `install-node.sh`, `aws-validate-acl.sh`, `tf-validate-export.sh`, `final-check.sh` |
| `deploy-waf/` | WAF all-in-one in un container (davanti a un nginx esistente), con README dettagliato |
| `deploy-waf-for-odoo/` | stack locale completo: WAF, nginx, Odoo 14, Postgres, ClickHouse, Prometheus, Grafana |
| `.github/workflows/images.yml` | build e pubblicazione delle immagini su ghcr.io (sotto) |
| `data/` | liste IP e definizioni AWS scaricate |
| `docs/` | documentazione (sotto) e piani (`docs/plans/`) |

## Immagini Docker

Il workflow `.github/workflows/images.yml` pubblica su GitHub Container Registry, per amd64 e arm64:

| Immagine | Dockerfile |
|---|---|
| `ghcr.io/manprint/nginx-aws-waf/aio` | `deploy-waf/Dockerfile` |
| `ghcr.io/manprint/nginx-aws-waf/waf` | `waf/Dockerfile` |
| `ghcr.io/manprint/nginx-aws-waf/nikto` | `lab/nikto/Dockerfile` |

Tag: `latest` (push su `main`), `<sha8>` (ogni build), `vX.Y.Z` (push di un tag git `vX.Y.Z`).
Nelle pull request le immagini vengono solo costruite. Dettagli in
[deploy-waf/README.md](deploy-waf/README.md#15-immagini-pubblicate).

## Documentazione

- [docs/rules-spec.md](docs/rules-spec.md) — regole AWS e come sono riprodotte, schema ID
- [docs/config-reference.md](docs/config-reference.md) — tutte le chiavi di configurazione
- [docs/tuning.md](docs/tuning.md) — flusso shadow → count + label rule → enforce, bypass
- [docs/operations.md](docs/operations.md) — percorsi, apply/rollback, systemd, log, centrale, segreti
- [docs/observability.md](docs/observability.md) — eventi, ClickHouse, `wafctl logs/stats/report`, export AWS
- [docs/dashboards-alerts.md](docs/dashboards-alerts.md) — Grafana, dashboard, alert, apprise, utenti, accesso
- [docs/multi-node.md](docs/multi-node.md) — topologia, porte, PKI e mTLS, enrollment/rinnovo/revoca, installazione, Tailscale, Terraform
- [docs/aws-export.md](docs/aws-export.md) — export verso AWS WAF (JSON, Terraform), mappatura, lossy, validazione
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
