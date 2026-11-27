# deploy-waf — WAF davanti al tuo nginx

Mette un **WAF in stile AWS WAF** (nginx + ModSecurity, con le regole "one-click" di AWS:
IpReputation, CommonRuleSet, KnownBadInputs) davanti al **tuo nginx esistente**, senza toccarne le
configurazioni. Pubblica anche le **metriche Prometheus**.

```
                    ┌──────────────────────── docker compose ─────────────────────────┐
 client ──80/443──► │  waf  ──── https (rete interna) ────►  nginx (le tue config)  ──┼──► applicazioni
                    │   │                                                              │
                    │   └─ log ──► metrics (Vector) ──► :9598/metrics                  │
                    └──────────────────────────────────────────────────────────────────┘
```

- **waf** è l'unico servizio esposto su 80/443. Termina l'HTTPS, ispeziona ogni richiesta, blocca
  gli attacchi con 403 e passa le altre a nginx.
- **nginx** è il tuo nginx, con le sue config di sempre. Non espone più porte: lo raggiunge solo il WAF.
- **metrics** legge i log del WAF e pubblica le metriche su `http://<host>:9598/metrics`.

---

## Indice

1. [Requisiti](#1-requisiti)
2. [Contenuto della cartella](#2-contenuto-della-cartella)
3. [Prova rapida](#3-prova-rapida-5-minuti)
4. [Usarlo con il tuo nginx](#4-usarlo-con-il-tuo-nginx)
5. [Certificati HTTPS](#5-certificati-https)
6. [Opzioni (.env)](#6-opzioni-env)
7. [Messa in produzione: prima osserva, poi blocca](#7-messa-in-produzione-prima-osserva-poi-blocca)
8. [Log: cosa è stato bloccato e perché](#8-log-cosa-è-stato-bloccato-e-perché)
9. [Metriche Prometheus](#9-metriche-prometheus)
10. [Comandi di gestione](#10-comandi-di-gestione)
11. [Più domini con certificati diversi](#11-più-domini-con-certificati-diversi)
12. [Installazione su una macchina senza internet](#12-installazione-su-una-macchina-senza-internet)
13. [Problemi comuni](#13-problemi-comuni)
14. [Come funziona dentro](#14-come-funziona-dentro)

---

## 1. Requisiti

- Docker Engine e il plugin `docker compose` v2.24 o successivo (`docker compose version`).
- Le porte 80 e 443 libere sull'host: le prende il WAF.
- Il certificato e la chiave HTTPS dei tuoi domini, gli stessi che usa già il tuo nginx.
- Per la build: questa cartella dentro il repository `nginx_aws_waf`, perché la build usa i file
  della root. Sul server di destinazione, invece, basta l'immagine già costruita
  ([sezione 12](#12-installazione-su-una-macchina-senza-internet)).

## 2. Contenuto della cartella

| Percorso | Cosa contiene | Lo modifichi? |
|---|---|---|
| `docker-compose.yml` | i tre servizi: `waf`, `metrics` e `nginx` (d'esempio) | **sì**: metti il tuo nginx al posto di quello d'esempio |
| `.env.example` | tutte le opzioni, commentate | copialo in `.env` e modificalo |
| `nginx/default.conf` | config nginx d'esempio | sostituiscila con le tue |
| `certs/app/` | `fullchain.pem` + `privkey.pem` del tuo dominio | **sì** |
| `logs/` | log del WAF (li crea il container) | no |
| `data/` | dati generati dai container: `runtime/` (config nginx generate), `lists/` (liste IP), `state/` (bypass), `raw/` (eventi JSONL), `vector/` (stato di Vector) | no |
| `config/sites/` | siti aggiuntivi in YAML ([sezione 11](#11-più-domini-con-certificati-diversi)) | solo se serve |
| `config/lists/` | liste IP personali da bloccare | solo se serve |
| `config/examples/` | esempi commentati con tutte le opzioni | no |
| `geoip/` | database GeoLite2, per il blocco per paese | solo se serve |
| `vector/` | pipeline di log e metriche | no |
| `Dockerfile`, `bin/` | build dell'immagine del WAF | no |

## 3. Prova rapida (5 minuti)

Con il nginx d'esempio e un certificato autofirmato:

```sh
cd deploy-waf
cp .env.example .env

# certificato di prova (in produzione usa il tuo, vedi sezione 5)
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=app.interno.local \
  -keyout certs/app/privkey.pem -out certs/app/fullchain.pem
chmod 644 certs/app/*.pem

docker compose up -d --build        # la prima build richiede circa 1 minuto
docker compose ps                   # waf deve risultare "healthy"
```

Verifica:

```sh
# HTTP → redirect a HTTPS
curl -I -H 'Host: app.interno.local' http://127.0.0.1/

# richiesta normale → 200, risponde nginx
curl -k --resolve app.interno.local:443:127.0.0.1 https://app.interno.local/

# attacco XSS → 403, bloccato dal WAF
curl -k -o /dev/null -w '%{http_code}\n' --resolve app.interno.local:443:127.0.0.1 \
  'https://app.interno.local/?q=<script>alert(1)</script>'

# metriche
curl -s http://127.0.0.1:9598/metrics | grep ^waf_
```

Per spegnere: `docker compose down`. Non ci sono volumi docker: tutto sta in bind mount dentro questa
cartella (`logs/`, `data/`). Per ripartire da zero: `docker compose down && sudo rm -rf data/* logs/*.log*`.
I file in `data/` e `logs/` sono creati come root dai container.

## 4. Usarlo con il tuo nginx

Hai due possibilità.

### A) Porti il tuo nginx in questo compose (più semplice)

Nel `docker-compose.yml` sostituisci il servizio `nginx` d'esempio con il tuo: stessa immagine,
stessi volumi, stesse reti, stesso `depends_on`. Cambiano solo due cose:

1. **Togli la sezione `ports:`** del tuo nginx (le porte 80/443 ora sono del WAF).
2. **Il servizio si deve chiamare `nginx`**. Se ha un altro nome, per esempio `proxy`, imposta nel
   `.env` `WAF_UPSTREAM=proxy:443` e cambia `depends_on: [nginx]` del servizio `waf`.

```yaml
  nginx:
    image: nginx:1.27-alpine              # la tua
    restart: unless-stopped
    # ports:                              ← RIMOSSO
    #   - "80:80"
    #   - "443:443"
    volumes:
      - /srv/mio-nginx/conf.d:/etc/nginx/conf.d:ro
      - /srv/mio-nginx/certs:/etc/nginx/certs:ro
      - /srv/mio-nginx/html:/usr/share/nginx/html:ro
```

### B) Il tuo nginx resta nel suo compose

1. Nel compose del tuo nginx **togli `ports:`** e fai `docker compose up -d`.
2. Trova la rete del tuo nginx:
   ```sh
   docker inspect <container-nginx> -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'
   # es. mioprogetto_default
   ```
3. In questo `docker-compose.yml` cancella il servizio `nginx` e la riga `depends_on: [nginx]`.
   Poi collega `waf` a quella rete:
   ```yaml
   services:
     waf:
       # ...
       networks: [default, frontend]
   networks:
     frontend:
       external: true
       name: mioprogetto_default
   ```
4. Nel `.env` imposta `WAF_UPSTREAM=<nome-servizio-o-container-nginx>:443`.

### Il tuo nginx è solo HTTP (niente 443)?

```env
WAF_UPSTREAM=nginx:80
WAF_UPSTREAM_TLS=false
```

L'HTTPS verso i client lo fa comunque il WAF (`WAF_TLS_MODE=redirect`). Attenzione: se il tuo nginx
sulla porta 80 fa `return 301 https://...`, con questa configurazione va in loop. In quel caso
lascia `nginx:443`.

### Cosa riceve il tuo nginx

- Lo stesso header `Host` del client, quindi i tuoi `server_name` scelgono il sito giusto come prima.
- L'IP reale del client negli header `X-Real-IP` e `X-Forwarded-For`. `$remote_addr` è invece
  l'IP del WAF. Per avere l'IP reale nei log del tuo nginx:
  ```nginx
  set_real_ip_from 172.16.0.0/12;   # reti docker
  real_ip_header X-Real-IP;
  ```
- `X-Forwarded-Proto: https` e `X-Request-ID`. Quest'ultimo è lo stesso ID che trovi nei log del
  WAF, utile per correlare.

## 5. Certificati HTTPS

Per poter ispezionare il traffico HTTPS, il WAF deve decifrarlo: **termina lui il TLS**, con gli
stessi certificati del tuo nginx. Poi riapre una connessione HTTPS verso nginx sulla rete interna
di docker.

```
certs/app/fullchain.pem    # certificato + catena intermedia
certs/app/privkey.pem      # chiave privata
```

- `app` è il nome del sito (`WAF_SITE_ID`, default `app`).
- Un certificato wildcard o multi-dominio (SAN) copre tutti i domini con un solo sito.
  Se hai certificati diversi per domini diversi, vedi la [sezione 11](#11-più-domini-con-certificati-diversi).
- **Senza certificati il WAF non parte** quando `WAF_TLS_MODE` è `on` o `redirect`. Se vuoi solo
  HTTP, imposta `WAF_TLS_MODE=off`.
- **Rinnovo:** invece di copiare i file, monta la cartella dove li rinnova già il tuo sistema
  (certbot, acme.sh, ecc.):
  ```yaml
      volumes:
        - /etc/letsencrypt/live/app.interno.local:/etc/waf/certs/app:ro
  ```
  Con Let's Encrypt i file in `live/` sono link simbolici verso `archive/`: in quel caso monta
  `/etc/letsencrypt` intero e usa `config/sites/` con `tls.cert`/`tls.key`, oppure copia i file
  con un hook di rinnovo. Dopo un rinnovo: `docker compose exec waf waf reload -f`.

## 6. Opzioni (`.env`)

Le opzioni sono tutte in `.env.example`, ciascuna con un commento. Dopo una modifica al `.env` serve
`docker compose up -d`, che ricrea il container.

| Opzione | Default | Cosa fa |
|---|---|---|
| `WAF_SERVER_NAMES` | — | domini serviti, separati da virgola |
| `WAF_UPSTREAM` | `nginx:443` | dove va il traffico pulito |
| `WAF_UPSTREAM_TLS` | `true` | HTTPS verso nginx |
| `WAF_TLS_MODE` | `redirect` | `off` / `on` / `redirect` (HTTP → HTTPS) |
| `WAF_DEFAULT_SITE` | `app` | gli Host non elencati vanno comunque a nginx (vuoto = connessione chiusa) |
| `WAF_PROFILE` | `aws-default` | `aws-default`, `shadow` (solo log), `strict` (+SQLi, Tor), `odoo-NN` |
| `WAF_MODE` | (del profilo) | `enforce` = blocca, `count` = registra soltanto |
| `WAF_BODY_LIMIT` | `8192` | byte del body ispezionati (come AWS) |
| `WAF_MAX_BODY_SIZE` | `10m` | upload massimo |
| `WAF_READ_TIMEOUT_SEC` | `60` | timeout verso nginx |
| `WAF_RATE_LIMIT` / `_WINDOW_SEC` / `_ACTION` | off | richieste massime per IP nella finestra |
| `WAF_GEOIP`, `WAF_GEO_BLOCK`, `WAF_GEO_ACTION` | off | blocco per paese (servono le mmdb in `geoip/`) |
| `WAF_TRUSTED_PROXIES` | — | CIDR di un proxy/LB **davanti** al WAF: IP del client da `X-Forwarded-For` |
| `HTTP_PORT` / `HTTPS_PORT` / `BIND_ADDRESS` | 80 / 443 / 0.0.0.0 | porte sull'host |
| `METRICS_PORT` / `METRICS_BIND_ADDRESS` | 9598 / 0.0.0.0 | porta delle metriche |
| `WAF_LISTS_UPDATE` | `false` | aggiorna ogni giorno le liste IP di reputazione (serve internet) |
| `WAF_LOG_MAX_SIZE_MB` / `WAF_LOG_KEEP_HOURS` | 512 / 24 | rotazione dei log |

Per regole più fini (eccezioni per percorso, regole in count, allowlist IP, regole custom) servono
i file YAML in `config/sites/`: vedi `config/examples/site-full.yaml` e `../docs/config-reference.md`.

### Cosa blocca il profilo `aws-default`

È la stessa web ACL "one-click" che AWS propone per un ALB:

| Gruppo | Esempi di cosa blocca |
|---|---|
| `AWSManagedRulesAmazonIpReputationList` | IP noti per botnet e scansioni (liste open che approssimano quelle AWS) |
| `AWSManagedRulesCommonRuleSet` | XSS, LFI/path traversal, RFI, SSRF verso EC2 metadata, richieste senza User-Agent, body/query/cookie troppo grandi, estensioni riservate |
| `AWSManagedRulesKnownBadInputsRuleSet` | Log4Shell, Java deserialization, percorsi sfruttabili, `localhost` nell'Host, ecc. |

**SQL injection non è nel default AWS.** Se ti serve, usa `WAF_PROFILE=strict`.

## 7. Messa in produzione: prima osserva, poi blocca

Un WAF nuovo può bloccare richieste legittime della tua applicazione (falsi positivi).
Procedura consigliata:

1. **Osservazione (qualche giorno):** `WAF_PROFILE=shadow`. Non blocca niente, ma registra cosa
   *avrebbe* bloccato.
   ```sh
   docker compose up -d
   ```
2. **Controlla cosa sarebbe stato bloccato:**
   ```sh
   curl -s http://127.0.0.1:9598/metrics | grep 'waf_requests_total.*shadow_action="BLOCK"'
   curl -s http://127.0.0.1:9598/metrics | grep waf_rule_matches_total
   ```
   Oppure guarda i log ([sezione 8](#8-log-cosa-è-stato-bloccato-e-perché)).
3. **Correggi i falsi positivi:** metti in count solo la regola che sbaglia, eventualmente solo su
   un percorso. Per farlo crea `config/sites/app.yaml` (vedi [sezione 11](#11-più-domini-con-certificati-diversi))
   con, per esempio:
   ```yaml
   rule_groups:
     - name: AWSManagedRulesCommonRuleSet
       rule_action_overrides: {SizeRestrictions_BODY: count}
   path_overrides:
     - {path_prefix: /api/upload, rules: {CrossSiteScripting_BODY: count}}
   ```
4. **Attiva il blocco:** `WAF_PROFILE=aws-default`, poi `docker compose up -d`.

**Emergenza** (il WAF blocca qualcosa di importante): metti il sito in sola registrazione per
30 minuti, senza toccare la config.

```sh
docker compose exec waf waf bypass app --ttl 30m --reason "blocca il checkout"
docker compose exec waf waf bypass list
docker compose exec waf waf bypass clear app      # per toglierlo prima della scadenza
```

## 8. Log: cosa è stato bloccato e perché

Tutto in `logs/`:

| File | Contenuto |
|---|---|
| `access.log` | una riga JSON per richiesta: `rid`, `site`, `host`, `ra` (IP client), `uri`, `status`, `rt` (tempo) |
| `audit.log` | per le richieste ispezionate: regole matchate, label AWS, header e body (JSON ModSecurity) |
| `error.log` | errori di nginx e una riga leggibile per ogni blocco (`AWSWAF_BLOCK`) |

Gli eventi già elaborati (una riga per richiesta, con la regola che ha bloccato) sono in
`data/raw/<giorno>/events.jsonl` e `matches.jsonl`:

```sh
# ultime richieste bloccate: regola, IP, URI
cat data/raw/*/events.jsonl \
  | jq -c 'select(.action=="BLOCK") | {ts, client_ip, method, uri, terminating_rule}' | tail -20

# tutte le regole matchate (anche quelle in count), ultime 20
cat data/raw/*/matches.jsonl \
  | jq -c '{ts, client_ip, path, rule_group, rule_name, configured_action, request_action}' | tail -20

# i 403 dall'access log
grep '"status":403' logs/access.log | jq -c '{ts, ra, uri, rid}' | tail
```

Il campo `rid` (o `request_id`) è lo stesso valore dell'header `X-Request-ID` che arriva al tuo
nginx.

I log vengono ruotati oltre `WAF_LOG_MAX_SIZE_MB`, compressi con gzip e cancellati dopo
`WAF_LOG_KEEP_HOURS`. Gli eventi JSONL vengono cancellati dopo `WAF_RAW_DAYS` giorni.

## 9. Metriche Prometheus

Endpoint: `http://<host>:9598/metrics`

### Metriche del WAF

| Metrica | Label | Significato |
|---|---|---|
| `waf_requests_total` | `site`, `action` (ALLOW/BLOCK/FAIL), `shadow_action`, `mode`, `status` | richieste gestite dal WAF |
| `waf_blocked_requests_total` | `site`, `rule`, `type` | richieste bloccate, per regola che ha bloccato |
| `waf_rule_matches_total` | `site`, `rule_group`, `rule`, `configured_action`, `request_action` | match per regola, comprese quelle in count |
| `waf_request_duration_seconds` | `site` | istogramma della latenza totale vista dal client |
| `waf_upstream_duration_seconds` | `site` | istogramma della latenza del tuo nginx/backend |

`shadow_action` dice cosa sarebbe successo in modalità enforce. In modalità `shadow`/`count` ti
indica cosa verrebbe bloccato attivando il blocco.

### Altre metriche (label `node_id`)

- `nginx_*`: connessioni attive, richieste totali, ecc. del WAF (stub_status).
- `host_*`: CPU, memoria, load, dischi e rete **dell'host**.
- `vector_*`: salute della pipeline di raccolta.

### Configurazione di Prometheus

```yaml
scrape_configs:
  - job_name: waf
    scrape_interval: 15s
    static_configs:
      - targets: ["10.0.0.5:9598"]      # IP della macchina con il WAF
```

### Query utili (PromQL)

```promql
# richieste/s per esito
sum by (action) (rate(waf_requests_total[5m]))

# % di richieste bloccate
sum(rate(waf_requests_total{action="BLOCK"}[5m])) / sum(rate(waf_requests_total[5m]))

# top 10 regole che bloccano
topk(10, sum by (rule) (increase(waf_blocked_requests_total[1h])))

# in shadow: cosa verrebbe bloccato
sum by (site) (rate(waf_requests_total{shadow_action="BLOCK", action="ALLOW"}[5m]))

# latenza p95 del backend
histogram_quantile(0.95, sum by (le) (rate(waf_upstream_duration_seconds_bucket[5m])))

# errori 5xx
sum(rate(waf_requests_total{status=~"5.."}[5m]))
```

Proposta di alert: % bloccate > 20 % per 10 minuti (attacco o falso positivo dopo un deploy),
`up{job="waf"} == 0`, 5xx > 1 %.

> La porta 9598 non ha autenticazione. Su una rete non fidata usa `METRICS_BIND_ADDRESS=127.0.0.1`
> o un firewall che la apra solo al server Prometheus.

## 10. Comandi di gestione

Si eseguono con `docker compose exec waf waf <comando>`:

| Comando | Effetto |
|---|---|
| `waf status` | config attiva, siti, stato di nginx, liste IP |
| `waf validate` | verifica la configurazione |
| `waf config` | mostra la configurazione effettiva, compresa quella generata dal `.env` |
| `waf explain app` | regole, azioni e override effettivi del sito |
| `waf reload [-f]` | rigenera e ricarica subito (altrimenti avviene da solo entro 30 s) |
| `waf rollback <rev>` | torna a una versione precedente della config (`ls` in `/etc/waf/runtime`) |
| `waf bypass app --ttl 30m --reason "..."` | sito in sola registrazione per un tempo limitato |
| `waf bypass list` / `waf bypass clear app` | elenca / rimuove i bypass |
| `waf lists-update` | scarica le liste IP aggiornate (serve internet) |
| `waf rotate` | ruota i log subito |

Altri comandi utili:

```sh
docker compose logs -f waf                 # errori di config e reload
docker compose exec waf nginx -T -c /etc/waf/runtime/current/nginx/nginx.conf | less   # config nginx generata
docker compose pull nginx && docker compose up -d                                       # aggiorna il tuo nginx
docker compose build waf && docker compose up -d                                        # aggiorna il WAF
```

**Bloccare IP a mano:** scrivili, uno per riga (IP o CIDR), in
`config/lists/custom-reputation.txt`. Vengono applicati entro 30 secondi. Per disattivarli svuota
il file invece di cancellarlo.

## 11. Più domini con certificati diversi

Le variabili del `.env` definiscono **un** sito (`app`). Per più siti crea un file per sito in
`config/sites/`. Il nome del file deve coincidere con `site_id`. I file vengono letti entro
30 secondi, senza riavvio.

`config/sites/shop.yaml`:

```yaml
version: 1
site_id: shop
server_names: [shop.interno.local]
app: generic
profile: aws-default
upstream: {servers: ["nginx:443"], tls: true}
tls: {mode: redirect}            # certificati in certs/shop/fullchain.pem e privkey.pem
```

`config/sites/gestionale.yaml`:

```yaml
version: 1
site_id: gestionale
server_names: [gestionale.interno.local]
app: generic
profile: shadow                  # questo ancora in osservazione
upstream: {servers: ["nginx:443"], tls: true, max_body_size: 100m}
tls: {mode: redirect}
```

Ogni sito ha la sua cartella `certs/<site_id>/` e la sua etichetta `site` nelle metriche.
Se vuoi **solo** siti da file, nel `.env` imposta `WAF_UPSTREAM=` e `WAF_DEFAULT_SITE=` vuoti
(oppure `WAF_DEFAULT_SITE=shop`, cioè uno dei tuoi siti).
Tutte le opzioni di un sito sono in `config/examples/site-full.yaml`.

## 12. Installazione su una macchina senza internet

Sul PC con il repository e accesso a internet:

```sh
cd deploy-waf
docker compose build
docker pull timberio/vector:0.62.0-alpine
docker save nginx-aws-waf/aio:latest timberio/vector:0.62.0-alpine | gzip > waf-images.tar.gz
tar czf deploy-waf.tar.gz --exclude='logs/*.log*' --exclude='data/*/*' ../deploy-waf
```

Copia `waf-images.tar.gz` e `deploy-waf.tar.gz` sul server, poi:

```sh
docker load < waf-images.tar.gz
tar xzf deploy-waf.tar.gz && cd deploy-waf
cp .env.example .env && vi .env
# certificati in certs/app/, il tuo nginx nel docker-compose.yml
docker compose up -d --no-build
```

Le liste IP di reputazione sono quelle copiate nell'immagine al momento della build. Per averle
aggiornate, ricostruisci l'immagine con `docker compose build --build-arg FETCH_LISTS=1`.

## 13. Problemi comuni

| Sintomo | Causa / soluzione |
|---|---|
| `waf` si riavvia di continuo | `docker compose logs waf`. Di solito mancano i certificati in `certs/app/` (oppure usa `WAF_TLS_MODE=off`) o c'è un errore nel YAML. |
| `Bind for 0.0.0.0:80 failed: port is already allocated` | il tuo nginx (o un altro servizio) espone ancora la porta 80/443: togli il suo `ports:` |
| 502 Bad Gateway | il WAF non raggiunge nginx: controlla `WAF_UPSTREAM`, che nginx sia sulla stessa rete e che ascolti su quella porta (`docker compose exec waf wget -qO- --no-check-certificate https://nginx:443`) |
| Redirect infinito | `WAF_UPSTREAM=nginx:80` verso un nginx che rimanda a https: usa `nginx:443` + `WAF_UPSTREAM_TLS=true` |
| 403 su richieste legittime | trova la regola (sezione 8) e mettila in count per quel sito/percorso (sezione 7); in emergenza `waf bypass` |
| Il dominio risponde con connessione chiusa | Host non in `WAF_SERVER_NAMES` e `WAF_DEFAULT_SITE` vuoto |
| Nei log di nginx tutti gli IP sono uguali | è l'IP del WAF: usa `X-Real-IP` (sezione 4) |
| Upload grandi rifiutati con 413 | aumenta `WAF_MAX_BODY_SIZE` |
| Body grandi bloccati da `SizeRestrictions_BODY` | regola AWS sui body > 8 KB: mettila in count per quel percorso (sezione 7) |
| `metrics` non parte | parte solo quando `waf` è healthy: `docker compose logs metrics` |
| Nessuna metrica `waf_*` | compaiono dopo la prima richiesta passata dal WAF |

## 14. Come funziona dentro

- L'immagine `nginx-aws-waf/aio` contiene nginx con libmodsecurity v3, il catalogo delle regole
  (`../waf/catalog/rules.yaml`), i profili, le liste IP e `wafctl`.
- All'avvio, e ogni `WAF_WATCH_INTERVAL` secondi, il container:
  1. costruisce la configurazione da `.env` e `config/`;
  2. la traduce con `wafctl` in config nginx + ModSecurity, in una nuova versione sotto
     `/etc/waf/runtime/<rev>`;
  3. la verifica con `nginx -t`. Se non è valida resta attiva quella precedente e l'errore va nei
     log del container;
  4. sposta il puntatore `current` alla nuova versione e ricarica nginx senza interrompere le
     connessioni.
- Le ultime 5 versioni restano disponibili per `waf rollback`.
- La pipeline Vector (`vector/node.yaml`) unisce `access.log` e `audit.log` in un evento per
  richiesta, con la regola che ha bloccato, le label AWS e l'azione. `vector/metrics.yaml` ne
  ricava le metriche.
- Il formato degli eventi e i nomi di regole e label sono gli stessi di AWS WAF: un sito provato
  qui si può esportare come web ACL AWS (`../docs/aws-export.md`).
