# Operazioni sul nodo

## Percorsi (D19)

| Variabile | Contenuto |
|---|---|
| `$WAF_HOME` | questo repo (prodotto: catalogo, profili, compose, script) |
| `$WAF_CONFIG_DIR` | config del nodo (repo git per nodo): `node.yaml`, `sites/`, `profiles/`, `pages/`, `state/` |
| `$WAF_DATA_DIR` | dati: `runtime/<rev>`, `runtime/current`, `lists/`, `logs/`, `raw/<giorno>/`, `certs/<sito>/`, `geoip/`, `vector/`, `state/audit-slot` |
| `$WAF_CENTRAL_DIR` | dati del centrale (default `$WAF_DATA_DIR/central`): `clickhouse/`, `vector/` |

Nel lab `source scripts/lab-env.sh` imposta `WAF_HOME`, `WAF_CONFIG_DIR=lab/config`,
`WAF_DATA_DIR=.run` e il `PATH` per `wafctl`. In produzione le variabili stanno in
`/etc/default/wafctl` (letto dalle unit systemd).

Mount del container `waf`: `runtime` → `/etc/waf/runtime` (ro), `lists` → `/etc/waf/lists` (ro),
`certs` → `/etc/waf/certs` (ro), `geoip` → `/etc/waf/geoip` (ro), `logs` → `/var/log/waf`.
Certificati e chiavi non vanno mai in git.

## Apply e rollback

`wafctl apply`:

1. valida (exit 2 se ci sono errori);
2. renderizza in `runtime/<rev>` (rev = `YYYYMMDDTHHMMSSZ-<hash>`; una rev identica viene riusata);
3. `nginx -t` sulla nuova rev: se fallisce la rev viene cancellata ed esce 1, la config attiva resta;
4. sposta atomicamente il link `runtime/current`;
5. `nginx -s reload` e attesa che i worker servano la nuova rev (`127.0.0.1:8090/__rev`), oppure avvio
   del compose se il nodo è fermo;
6. tiene le ultime 5 rev più quella attiva.

Rollback manuale a una rev precedente:

```bash
ln -sfn <rev> $WAF_DATA_DIR/runtime/current.new && mv -T $WAF_DATA_DIR/runtime/current.new $WAF_DATA_DIR/runtime/current
docker compose -p waf exec -T waf nginx -s reload -c /etc/waf/runtime/current/nginx/nginx.conf
```

Il modo normale resta correggere la config (git revert nel repo del nodo) e rifare `wafctl apply`.

## Unit systemd (`deploy/systemd/`)

| Unit | Quando | Cosa |
|---|---|---|
| `wafctl-bypass-expire.timer` / `.service` | ogni minuto | `wafctl bypass expire`: rimuove i bypass scaduti e riapplica solo se è cambiato qualcosa |
| `wafctl-logs.timer` / `.service` | ogni ora | `wafctl logs rotate` |
| `wafctl-node-renew.timer` / `.service` | ogni giorno (+ fino a 1 h casuale) | `wafctl node renew`: rinnova il certificato del nodo se mancano meno di 30 giorni (ruolo node) |
| `wafctl-pki-crl.timer` / `.service` | ogni giorno | `wafctl pki crl`: rigenera la CRL (vale 7 giorni) e ricarica l'ingress (centrale) |
| `wafctl-pki.service` | sempre attivo | `wafctl pki serve --addr :6001`: API di enrollment/rinnovo (centrale) |

Installazione: `wafctl node bootstrap ... --install-systemd` copia le unit e abilita quelle del
ruolo ([multi-node.md](multi-node.md)). In alternativa, a mano: copiare i file in
`/etc/systemd/system/` e `wafctl` in `/usr/local/bin/`, poi eseguire
`systemctl daemon-reload && systemctl enable --now <unit>`.

## Log e rotazione

| File | Contenuto |
|---|---|
| `logs/access.log` | access log nginx JSON, una riga per richiesta (UTC) |
| `logs/audit.log` | audit log ModSecurity JSON (header e body della richiesta, match, `AWSWAF_SUMMARY`) |
| `logs/error.log` | errori nginx e messaggi ModSecurity |
| `raw/<YYYY-MM-DD>/events.jsonl` | eventi uniti da Vector (un evento per richiesta) |
| `raw/<YYYY-MM-DD>/matches.jsonl` | una riga per regola matchata |

`wafctl logs rotate [--max-size 512MiB] [--keep-hours 24] [--raw-days 7]`: rinomina i log oltre la
soglia in `<nome>.<YYYYMMDDTHHMMSSZ>`, fa `nginx -s reopen`, cancella i ruotati più vecchi di
`keep-hours` e le directory `raw/` più vecchie di `raw-days`.

Nota sull'audit log: libmodsecurity tiene aperti i file per nome anche attraverso i reload, quindi
un reload da solo continuerebbe a scrivere nel file rinominato. Quando ruota `audit.log`, `wafctl`
alterna lo "slot" (`state/audit-slot`: `SecAuditLog /var/log/waf/audit.log` ↔
`/var/log/waf//audit.log`, stesso file con un nome diverso) e fa un apply: il reload apre un
`audit.log` nuovo senza perdere righe e senza riavviare nginx.

## Stack centrale e segreti

Il ruolo in `node.yaml` sceglie i file compose usati da `wafctl apply`:

| `role` | File |
|---|---|
| `node` | `node.yml` + `node.<network>.yml` |
| `central` | `central.yml` |
| `all-in-one` | entrambi; in bridge anche `central.bridge.yml` |

Le password di ClickHouse si generano una sola volta sul centrale:

```bash
wafctl secrets init          # crea $WAF_CONFIG_DIR/secrets.env (0600); --force le rigenera
```

Il file contiene `WAF_CH_ADMIN_PASSWORD`, `WAF_CH_INGEST_PASSWORD`, `WAF_CH_RO_PASSWORD` e
`GF_ADMIN_PASSWORD` (admin di Grafana). `wafctl` lo passa al compose con `--env-file`. È escluso da
git e non va mai committato. Rilanciare `wafctl secrets init` aggiunge solo le chiavi mancanti.

Le password vengono applicate solo al **primo** avvio di ClickHouse (`initdb`). Se le rigeneri
dopo, devi aggiornare anche gli utenti in ClickHouse, oppure ripartire da `clickhouse/` vuota.

Quando cambia `vector/forward.yaml` (indirizzo del centrale), `wafctl apply` riavvia `vector`.

Sul centrale `wafctl apply` legge anche `$WAF_CONFIG_DIR/central.yaml` (Grafana, soglie degli
alert, file degli URL apprise, retention). Prima del compose up genera in `$WAF_CENTRAL_DIR` i
file di Prometheus, Grafana (datasource, dashboard, alert) e apprise, e riavvia solo i servizi i
cui file sono cambiati. Gli stessi file si generano senza applicare con `wafctl central render`.
Nel repo del centrale metti `apprise-urls.txt` nel `.gitignore`: contiene token.
Dettagli in [dashboards-alerts.md](dashboards-alerts.md).

Cambiare l'indirizzo `listen` di nginx (per esempio la porta di stato 8090 in bridge) non si
applica con un reload, perché nginx non riesce a fare il bind (`Address in use`). In quel caso
`wafctl apply` ripristina `current` alla revisione precedente e lo segnala. Esegui
`docker compose restart waf` (oppure `docker restart <progetto>-waf-1`) e poi di nuovo
`wafctl apply`.

Sul centrale, dopo ogni aggiornamento di `wafctl`:

```bash
wafctl ch migrate                       # migrazioni dello schema (idempotente)
wafctl ch retention                     # TTL attuali; --raw-days N / --agg-days M per cambiarli
```

Il disco del centrale cresce con la retention degli eventi grezzi (default 30 giorni). Le tabelle
aggregate (400 giorni) sono piccole. Dettagli in [observability.md](observability.md).

## Liste IP

Le liste usate dalle regole di reputazione stanno in `$WAF_DATA_DIR/lists/*.txt` (montate in
`/etc/waf/lists`). Nel lab `make lists` le copia da `data/ip-reputation/` (`make fetch` le scarica).
L'aggiornamento automatico (`wafctl lists`) arriva nella fase 6 (unità 6.4); dopo un cambio delle
liste serve un reload (`wafctl apply`).

## Benchmark

Vedi `docs/performance.md` (`scripts/bench.sh`).
