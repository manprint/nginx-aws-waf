# Osservabilità: log, storage centrale, CLI

Ogni richiesta che passa dal WAF produce un **evento**. Ogni regola che ha matchato produce un
**match**. Gli eventi restano sul nodo in JSONL e vengono inoltrati allo storage centrale
(ClickHouse). `wafctl logs|stats|report` li interroga. Tutti i tempi sono in UTC.

## Flusso dei dati

```
nginx + ModSecurity ──► logs/access.log  (JSON, una riga per richiesta)
                    └─► logs/audit.log   (JSON: header, body, match, AWSWAF_SUMMARY)
        │
        ▼  Vector del nodo (deploy/vector/node.yaml + runtime/current/vector/forward.yaml)
  un'unica sorgente file per i due log → join per request_id (reduce, max 2 righe, scadenza 3 s)
        ├─► raw/<YYYY-MM-DD>/events.jsonl, matches.jsonl  (copia locale, sempre scritta)
        ├─► heartbeat: meta.json della rev attiva ogni 30 s
        └─► sink "vector" verso il centrale (buffer su disco 2 GiB, when_full: block)
                 │
                 ▼  vector-central (deploy/vector/central.yaml)
           arricchimento GeoIP: country (GeoLite2-Country), asn + as_org (GeoLite2-ASN)
                 │
                 ▼  ClickHouse: waf.events, waf.matches, waf.heartbeats
                    + viste materializzate → waf.agg_requests_1m, waf.agg_matches_1m
```

`wafctl apply` genera `vector/forward.yaml` secondo il ruolo (`role` in `node.yaml`):

| Ruolo | Destinazione |
|---|---|
| `all-in-one` (bridge) | `vector-central:6000`, in chiaro sulla rete locale |
| `all-in-one` (host) | `127.0.0.1:6100`, in chiaro su loopback |
| `node` | `central.address:central.ingest_port` (IPv6 ammesso), **mTLS** |
| nessun indirizzo | blackhole: restano solo i file `raw/` |

Un nodo remoto (`role: node`) si collega all'ingress mTLS del centrale: il sink usa
`tls {crt_file, key_file, ca_file, verify_hostname: true}` con il certificato client in
`$WAF_DATA_DIR/certs/_node/{node.pem,node.key,ca.pem}`. Per questo `central.address` deve essere
uno dei nomi (o IP) del certificato server dell'ingress (`ingress.server_names` / `server_ips` in
`central.yaml`).

Latenza tipica a regime: 4–8 s da richiesta a riga in ClickHouse. Il primo evento dopo un periodo
di inattività può arrivare fino a circa 13 s dopo, perché le sorgenti file e il buffer su disco di
Vector fanno backoff quando sono inattivi.

## Stack centrale

`deploy/compose/central.yml` contiene `clickhouse` (HTTP `127.0.0.1:8123`), `vector-central`
(ingest in chiaro sulla porta 6000, non pubblicata) e `ingress`. L'ingress è un nginx `stream`
pubblicato su `ingress.bind:ingress.ingest_port` (default `0.0.0.0:6000`). Termina l'mTLS
(`ssl_verify_client on`, `ssl_crl`, ALPN `h2`) e inoltra a `vector-central:6000`.

`wafctl apply` (e `wafctl central render`) genera `$WAF_CENTRAL_DIR/ingress/`:

- `nginx.conf`;
- `certs/`, con `ingress.pem`/`ingress.key`, `ca.pem` e `crl.pem`. La chiave della CA non viene
  mai copiata qui.

Il certificato server viene riemesso se manca, se scade entro 30 giorni o se cambiano i SAN.

`wafctl pki revoke` e `wafctl pki crl` copiano la nuova CRL e ricaricano l'ingress. Installare il
timer `deploy/systemd/wafctl-pki-crl.timer` (giornaliero): la CRL vale 7 giorni e, se scade, nginx
rifiuta tutti i nodi.

In modalità all-in-one bridge, `central.bridge.yml` collega anche `vector-central` e `ingress` alla
rete `waf_lab`. In modalità host, `central.host.yml` pubblica `vector-central` su
`127.0.0.1:6100` per il nodo locale. I dati stanno in `$WAF_CENTRAL_DIR` (default
`$WAF_DATA_DIR/central`): `clickhouse/`, `vector/` e `ingress/`.

Utenti ClickHouse (le password stanno in `$WAF_CONFIG_DIR/secrets.env`, generate da
`wafctl secrets init`, permessi 0600, mai in git):

| Utente | Uso | Permessi |
|---|---|---|
| `waf_admin` | `wafctl ch migrate`, `wafctl ch retention`, amministrazione | tutti |
| `waf_ingest` | vector-central | INSERT, SELECT su `waf.*` |
| `waf_ro` | `wafctl logs/stats/report`, Grafana | SELECT, `readonly=2` |

Variabili per `wafctl`:

| Variabile | Default |
|---|---|
| `WAF_CH_URL` | `http://127.0.0.1:8123` |
| `WAF_CH_USER` | `waf_ro` |
| `WAF_CH_PASSWORD` | `WAF_CH_RO_PASSWORD` letta da `secrets.env` |

`wafctl` usa l'interfaccia HTTP di ClickHouse con query costanti e parametri `{nome:Tipo}`. I valori
passano come `param_<nome>` e non vengono mai concatenati nell'SQL.

## Tabelle

Il DDL completo è in [deploy/clickhouse/initdb/001-schema.sql](../deploy/clickhouse/initdb/001-schema.sql).

| Tabella | Contenuto | TTL default |
|---|---|---|
| `waf.events` | una riga per richiesta (47 colonne: rete, HTTP, esito WAF, header, body) | 30 giorni |
| `waf.matches` | una riga per regola matchata (regola, gruppo, variabile, valore) | 30 giorni |
| `waf.heartbeats` | `meta.json` di ogni nodo ogni 30 s (rev attiva, siti) | 30 giorni |
| `waf.agg_requests_1m` | conteggi per minuto, nodo, sito, azione, azione AWS default, user_class, classe di status | 400 giorni |
| `waf.agg_matches_1m` | match per minuto, nodo, sito, regola, azione configurata, post_terminating, user_class | 400 giorni |

### Significato dei campi principali

| Campo | Valori | Significato |
|---|---|---|
| `action` | `ALLOW` `BLOCK` `FAIL` | Cosa ha fatto il WAF. `FAIL` = errore interno del motore: risposta 500 se il sito è fail-closed (default). |
| `shadow_action` | `ALLOW` `BLOCK` | Cosa avrebbe fatto la config del sito in enforce. Nei siti in `shadow` mode `action` è sempre `ALLOW` e questo campo dice cosa sarebbe successo. |
| `aws_default_action` | `ALLOW` `BLOCK` | Cosa farebbe l'ACL one-click AWS non tarata (IpReputation → CommonRuleSet → KnownBadInputs, tutto in Block). `action != aws_default_action` è un **disaccordo**. |
| `aws_default_rule` | `Gruppo/Regola` | La regola che avrebbe terminato su AWS. |
| `terminating_rule` | `Gruppo/Regola`, `custom:<sito>/<Nome>`, `Default_Action` | La regola che ha deciso. |
| `terminating_type` | `MANAGED_RULE_GROUP` `REGULAR` `DEFAULT` | Regola gestita, regola custom (label rule), azione di default. |
| `waf_mode` | `enforce` `shadow` | Modalità del sito. |
| `user_class` | `backend` `website` `static` `realtime` `other` | Classe del path, dal profilo dell'app (Odoo: `/web`, `/odoo` → backend, ecc.). |
| `labels` | `awswaf:managed:aws:…` | Etichette AWS prodotte dai match (anche dalle regole in Count). |
| `matches.configured_action` | `BLOCK` `COUNT` `ALLOW` | Azione configurata per la regola dopo profili, sito e bypass. |
| `matches.in_scope` | 0/1 | 0 = la regola ha matchato ma la scope-down del sito la esclude. |
| `matches.post_terminating` | 0/1 | 1 = match dopo la regola terminante. AWS non lo valuterebbe: serve solo alla diagnosi. |

## Comandi

Prima di tutto: `source scripts/lab-env.sh` nel lab, oppure `/etc/default/wafctl` in produzione.

### Ricerca e dettaglio

```bash
wafctl logs search --since 15m --action BLOCK --site demo
wafctl logs search --since 1h --rule NoUserAgent_HEADER --format json
wafctl logs search --since 1h --rule SizeRestrictions_BODY --matched   # anche dove era in COUNT
wafctl logs search --from 2026-11-27T00:00:00Z --to 2026-11-27T01:00:00Z --ip 198.51.100.10
wafctl logs show <request_id>                     # evento completo + tabella dei match
wafctl logs tail --site demo --action BLOCK       # nuove righe ogni 2 s, Ctrl-C per uscire
```

Filtri comuni:

| Filtro | Note |
|---|---|
| `--site S` | ripetibile |
| `--since DUR` | `15m`, `1h`, `7d`; default `1h` |
| `--from T [--to T]` | RFC3339 con fuso obbligatorio (`Z` o `+01:00`); senza fuso è un errore |
| `--action`, `--shadow`, `--rule NAME [--matched]` | `--rule` cerca la regola terminante; con `--matched` qualsiasi regola matchata |
| `--ip`, `--country`, `--path-prefix`, `--user-class`, `--status`, `--rid` | |
| `--limit N` | default 100, massimo 100000 |

### Statistiche

```bash
wafctl stats --since 1h                            # overview
wafctl stats --since 24h --by rule                 # GROUP RULE MATCHES TERMINATING COUNTED SITES
wafctl stats --since 24h --by rule --counted       # regole in COUNT che bloccherebbero: candidati
wafctl stats --since 1h --by path --sort-blocks --top 10
wafctl stats --since 1h --by country --format json     # anche ip, user_class, status, site
```

Con finestre di almeno 1 ora, `overview`, `site` e `rule` leggono le tabelle `agg_*`: sono veloci e
durano 400 giorni. L'inizio della finestra è allineato al minuto. Con finestre più brevi leggono gli
eventi grezzi.

### Report HTML

```bash
wafctl report --html --since 24h -o build/report.html
wafctl report --html --from 2026-11-01T00:00:00Z --to 2026-12-01T00:00:00Z --site shop16 -o build/nov.html
```

Il report è un unico file autocontenuto: CSS e grafici SVG inline, nessun riferimento esterno.

Sezioni:
1. riepilogo;
2. timeline oraria;
3. regole terminanti;
4. regole in COUNT;
5. disaccordi con AWS default;
6. path più bloccati;
7. IP e paesi;
8. eventi FAIL;
9. snapshot della config: `meta.json` e una riga aws-compatible/nginx-only per sito, se eseguito su un nodo.

### Modalità offline `--raw`

`logs search|show|export`, `stats` e `report` accettano `--raw DIR`. In questa modalità interrogano
i file `raw/<giorno>/*.jsonl` del nodo senza ClickHouse, con `clickhouse local` in un container
(`clickhouse/clickhouse-server:26.8-alpine`). L'SQL è lo stesso. Le tabelle `agg_*` diventano viste
calcolate dagli eventi, quindi su molti giorni la modalità offline è più lenta.

```bash
wafctl logs search --since 1h --action BLOCK --raw $WAF_DATA_DIR/raw
wafctl stats --since 24h --by rule --raw $WAF_DATA_DIR/raw
```

## Export

```bash
wafctl logs export --since 1h --format jsonl --with-matches --gzip -o build/events.jsonl.gz
wafctl logs export --from 2026-11-27T00:00:00Z --to 2026-11-28T00:00:00Z --format csv -o build/day.csv
wafctl logs export --since 15m --format aws -o - | jq .terminatingRuleId
```

L'export è in streaming e copre tutta la finestra (`--limit` non si applica).

| Formato | Contenuto |
|---|---|
| `jsonl` | righe di `waf.events`. Con `--with-matches` ogni riga ha anche `matches: [...]`. |
| `csv` | colonne di `waf.events` tranne `request_headers`, `response_headers`, `request_body`. La prima riga è l'intestazione. |
| `aws` | un record nel formato dei log AWS WAF per riga. |

### Mappatura del formato `aws`

| Campo AWS | Origine |
|---|---|
| `timestamp` | `ts` in millisecondi epoch |
| `formatVersion` | `1` |
| `webaclId` | `nginx-aws-waf:<node_id>:<site_id>` |
| `terminatingRuleId` | parte dopo l'ultima `/` di `terminating_rule`; `Default_Action` per l'azione di default |
| `terminatingRuleType` | `terminating_type`. Per `DEFAULT` e per le regole custom diventa `REGULAR`, come su AWS. |
| `action` | `action` |
| `httpSourceName` / `httpSourceId` | `ALB` / `site_id` |
| `ruleGroupList` | un elemento per gruppo gestito con match valutati da AWS (`in_scope=1`, `post_terminating=0`), in ordine di valutazione. `ruleGroupId` = `AWS#<gruppo>`. `terminatingRule` è valorizzato nel gruppo della regola terminante. I match con azione configurata COUNT vanno in `nonTerminatingMatchingRules`. |
| `nonTerminatingMatchingRules` (radice) | regole custom in COUNT |
| `responseCodeSent` | `status` se `action = BLOCK`, altrimenti `null` |
| `httpRequest` | `clientIp`, `country`, `headers` (ordinati per nome), `uri` = `path`, `args` = `query`, `httpVersion`, `httpMethod`, `requestId` |
| `labels` | `labels` |
| `terminatingRuleMatchDetails`, `rateBasedRuleList` | `[]` |
| `requestHeadersInserted`, `excludedRules` | `null` |

## Retention

| Dove | Manopola | Default |
|---|---|---|
| nodo, `raw/<giorno>/` | `wafctl logs rotate --raw-days N` (timer orario) | 7 giorni |
| nodo, log ruotati | `wafctl logs rotate --keep-hours N` | 24 ore |
| ClickHouse, `events` e `matches` | `wafctl ch retention --raw-days N` (1–3650) | 30 giorni |
| ClickHouse, `agg_*` | `wafctl ch retention --agg-days M` (M ≥ N) | 400 giorni |

```bash
wafctl ch retention                    # mostra i TTL attuali
wafctl ch retention --raw-days 20      # ALTER TABLE … MODIFY TTL
wafctl ch retention --raw-days 30 --agg-days 400
```

## Migrazioni dello schema

Il primo avvio di ClickHouse crea lo schema con i file `deploy/clickhouse/initdb/`.
`wafctl ch migrate` applica in ordine le migrazioni incluse nel binario (`migrations/NNN-*.sql`) e le
registra in `waf.schema_migrations`. La migrazione 001 è lo schema iniziale: se `waf.events` esiste
già viene solo segnata come applicata. Il comando è idempotente e va lanciato dopo ogni
aggiornamento di `wafctl` sul centrale (utente `waf_admin`).

## Database GeoIP

`vector-central` legge `$WAF_DATA_DIR/geoip/GeoLite2-Country.mmdb` e `GeoLite2-ASN.mmdb`, montati
in `/etc/waf/geoip`.

- **Lab:** `make geoip-test` scarica i database di test MaxMind. Contengono pochi IP, per esempio
  `2.125.160.216` → GB e `89.160.20.112` → SE / AS29518. `make lab-min-up` lo esegue se i file
  mancano.
- **Produzione:** usare i GeoLite2 reali, che richiedono un account MaxMind gratuito, per esempio
  con `geoipupdate`. Dopo l'aggiornamento: `docker compose -p waf restart vector-central`.

Se i file mancano, `vector-central` non parte. Se un IP non è nel database, `country` resta vuoto e
`asn` vale 0.
