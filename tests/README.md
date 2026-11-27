# Test

Tutti i comandi partono dalla root del repo dopo `source scripts/lab-env.sh`.

| Cosa | Comando | Note |
|---|---|---|
| Unit test Go | `make test-unit` | `cd wafctl && go test ./...` |
| Corpus richieste | `make test-e2e` | avvia il lab minimo e lancia `wafctl test run --suite tests/corpus` |
| Smoke del nodo | `tests/e2e/smoke.sh` | 200/403/444, log che crescono, T-R12 |
| Apply/bypass/explain | `tests/e2e/apply.sh` | I-5: un apply fallito non tocca la config attiva |
| Join log / centrale | `tests/e2e/joinlog.sh`, `tests/e2e/central.sh` | eventi uniti, inoltro a ClickHouse, GeoIP, heartbeat |
| CLI osservabilità | `tests/e2e/cli.sh` | `logs`, `export`, `stats`, `report`, `ch` |
| Metriche | `tests/e2e/metrics.sh` | target Prometheus up, metriche nginx e host per `node_id` |
| Grafana | `tests/e2e/grafana.sh`, `scripts/check-dashboards.sh` | dashboard, datasource, utenti, ogni query dei pannelli |
| Alert | `tests/e2e/alerts.sh [--spike-only]` | regole sane, test del contact point, picco di blocchi → notifica all'`alert-sink` (~4 min); `--spike-only` esegue solo il picco |
| Rate limit | `tests/e2e/ratelimit.sh` | sito `ratelimit` (10 req/60 s, block): 403 oltre il burst, `rl=REJECTED` nell'access log, eventi `RATE_BASED`/`BLOCK`; sito `ratecount` (count): tutto 200, `REJECTED_DRY_RUN` |
| Export AWS | `make aws-export-check`, `scripts/tf-validate-export.sh FILE.tf` | JSON di ogni sito del lab validato offline con la AWS CLI; Terraform con `terraform validate` in Docker |
| Liste IP | `wafctl lists update` | tabella `LIST OLD NEW STATUS`; offline tutte `kept` (exit 0) |
| Accettazione finale | `make final-check` | G-FINAL, 8 passi in ordine (lab-up + corpus, Playwright, ClickHouse ≤ 10 s + stats + dashboard, report HTML, export log AWS, bypass, alert, Terraform); log in `build/final-check/` (~10 min) |
| PKI | `tests/e2e/pki.sh` | CA, certificati client/server, revoca e CRL verificati con `openssl` (directory temporanea) |
| Bootstrap | `tests/e2e/bootstrap.sh` | tarball di release installato in un container `ubuntu:24.04` pulito; `install-node.sh` rifiuta senza Docker; `wafctl node bootstrap` + `validate`; un solo commit e nessun segreto tracciato |
| Multi-nodo | `tests/e2e/multinode.sh [part1]` | secondo nodo `waf2` (`.run2`, porta 18080) che inoltra via mTLS all'ingress; l'ingress rifiuta i client senza certificato. Parte 2 (~1 min): enrollment con token tramite `wafctl pki serve`, riuso del token → 403, `node renew --force`, revoca → nessun evento dal nodo revocato, re-enrollment finale |

## Corpus (`tests/corpus/*.yaml`)

Ogni caso invia una richiesta al nodo (default `http://127.0.0.1:8080`) con header
`X-Waf-Test: <runid>-<id>`; il runner poi legge l'audit log
(`$WAF_DATA_DIR/logs/audit.log`), prende `AWSWAF_SUMMARY` e le regole matchate e
confronta con `expect`.

```yaml
version: 1
cases:
  - id: crs-xss-query            # univoco in tutta la suite
    site: demo                   # Host = primo server_name del sito, salvo request.host
    request:
      method: GET                # default GET
      path: "/?q=<script>alert(1)</script>"   # inviato così com'è (nessuna normalizzazione)
      host: localhost            # opzionale
      headers: {User-Agent: ""}  # valore "" = header rimosso
      xff: 198.51.100.10         # default; "@list:AnonymousIPList.txt" = primo IP della lista
      body: "a=b"                # oppure body_repeat: {char: x, count: 9000, prefix: "a=", suffix: ""}
      content_type: ""           # default form-urlencoded se c'è un body
      multipart: {field: f, filename: x.html, content: "..."}
      chunked: false
    expect:
      status: 403
      terminating_rule: CrossSiteScripting_QUERYARGUMENTS   # o nome custom rule, o Default_Action
      matches: [CrossSiteScripting_QUERYARGUMENTS]          # sottoinsieme delle regole matchate (anche count)
```

Uscita: `OK|FAIL <id> status=… term=… matches=…` e `PASSED n/m`; exit 1 se un caso
fallisce o manca il record di audit. `--filter S` limita ai casi il cui id contiene `S`,
`--format json` per l'output macchina.

Richiesta singola: `wafctl test request --site demo --path '/?q=<script>' -H 'X-A: b'`.

I siti di lab sono in `lab/config/sites/` (demo, strict, tuned, shadow, allowlist);
`demo` ha anche i nomi `localhost` e `127.0.0.1` per i casi Host_localhost_HEADER.
Il nome IPv6 `[::1]` non è un server_name valido, quindi la variante IPv6 di quel caso
non è coperta dal corpus (lo copre la regola, verificata nel prototipo).

## Corpus sui siti Odoo (`make test-odoo`)

`wafctl test run --suite tests/corpus --filter-site demo --retarget demo=shopNN --exceptions tests/odoo-exceptions.yaml`
rilancia i casi del sito `demo` contro ogni sito Odoo. I siti speciali (`tuned`, `allowlist`,
`strict`, `shadow`) non vengono mai spostati. `tests/odoo-exceptions.yaml` sostituisce
l'attesa di un caso su alcuni siti; ogni eccezione deve avere un `reason` (altrimenti errore
di caricamento). I casi con `request.host` esplicito (localhost, 127.0.0.1) arrivano comunque
al sito `demo`, che ha quegli alias.
