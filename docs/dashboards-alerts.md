# Dashboard e alert

Il centrale (ruolo `central` o `all-in-one`) espone Grafana con 4 dashboard e 5 regole di alert. Le
notifiche partono da Grafana, passano da apprise e arrivano su Slack, Google Chat, Telegram o su uno
qualunque degli altri servizi supportati da apprise.

```
nodo: nginx ─ /nginx_status ┐
      host (/proc, /sys) ───┼─ Vector (m_host, m_nginx, m_vector, tag node_id) ──┐
      eventi/match/hb ──────┘                                                     │ HTTP (P5: mTLS)
centrale: vector-central ─┬─ ClickHouse (eventi, match, aggregati, heartbeat) ◄───┘
                          └─ :9598 prometheus_exporter ◄── Prometheus (scrape 15 s, retention 30 gg)
          Grafana ── datasource ClickHouse (waf_ro) + Prometheus ── alert ─► apprise ─► Slack/GChat/Telegram
```

## Accesso

Grafana ascolta su `grafana.bind` di `$WAF_CONFIG_DIR/central.yaml`. Il default è
`127.0.0.1:3000`, quindi Grafana non è raggiungibile da fuori. L'accesso anonimo e la registrazione
sono disattivati.

- **Tunnel SSH** (nessuna modifica di configurazione):

  ```bash
  ssh -N -L 3000:127.0.0.1:3000 utente@centrale
  # poi http://localhost:3000
  ```

- **Tailscale**: imposta `grafana.bind` sull'IP Tailscale del centrale e `grafana.root_url` sull'URL
  con cui lo apri. Poi esegui `wafctl apply`:

  ```yaml
  grafana: {bind: "100.64.0.10:3000", root_url: "http://centrale.tailnet-xyz.ts.net:3000/"}
  ```

Non usare `0.0.0.0` su un host esposto: Grafana non ha TLS proprio.

L'utente `admin` usa la password `GF_ADMIN_PASSWORD` in `$WAF_CONFIG_DIR/secrets.env`, generata da
`wafctl secrets init` (aggiunge solo le chiavi mancanti). Grafana la applica al primo avvio; per
cambiarla dopo usa l'interfaccia o `grafana cli admin reset-admin-password`.

## Utenti

```bash
wafctl grafana user add mario --name "Mario Rossi" --email mario@example.com --role Viewer
wafctl grafana user add ops --role Editor --password-stdin < password.txt
wafctl grafana user list
```

- Senza `--password-stdin` viene generata una password casuale di 20 caratteri, stampata **una sola
  volta**. Con `--password-stdin` la password deve avere almeno 8 caratteri.
- Ruoli ammessi: `Viewer` (sola lettura, il caso normale), `Editor`, `Admin`. Le dashboard sono
  provisionate e non modificabili dall'interfaccia, quindi `Editor` serve solo per esplorare.
- `wafctl` usa l'API di Grafana come `admin`. L'URL è `WAF_GRAFANA_URL`, default
  `http://127.0.0.1:3000`; dal tuo PC funziona attraverso il tunnel.

## Dashboard

Tutte le dashboard sono nella cartella **WAF**. Hanno fuso orario UTC, intervallo predefinito
6 ore e refresh ogni 30 s. Le dashboard con il filtro **Sito** accettano più siti o "All".

### WAF Overview (`waf-overview`)

Usa le tabelle aggregate al minuto, quindi è veloce anche su mesi di dati.

| Pannello | Cosa dice | Uso nel tuning |
|---|---|---|
| Richieste / Bloccate / Block % | volume e quota bloccata | un Block % che sale senza un attacco noto indica un falso positivo |
| FAIL | richieste chiuse con 500 dal fail-closed | deve stare a 0; altrimenti guarda `wafctl logs search --action FAIL` |
| Block AWS default | quante richieste avrebbe bloccato la web ACL one-click di AWS | è il riferimento per la migrazione |
| Disaccordi vs AWS default | richieste con azione diversa da quella di AWS default | sono le tue personalizzazioni: devono essere volute |
| Richieste per azione | ALLOW/BLOCK/FAIL nel tempo | i picchi di BLOCK sono attacchi o deploy dell'applicazione |
| Blocchi per sito | blocchi per sito nel tempo | mostra quale sito genera rumore |
| Classi di status | 2xx/3xx/4xx/5xx | i 5xx dell'upstream sono distinti dai FAIL del WAF |
| Regole terminanti (top) | regole che hanno deciso un blocco, escluse quelle in COUNT | sono le prime da verificare per i falsi positivi |
| Siti per blocchi | richieste, bloccate e % per sito | — |

### WAF Rules & Tuning (`waf-tuning`)

| Pannello | Cosa dice | Uso nel tuning |
|---|---|---|
| Regole in COUNT per sito (candidati would-block) | match delle regole messe in COUNT | sono le richieste che bloccheresti tornando a BLOCK. Se sono tutte legittime, tieni il COUNT con una label rule (vedi [tuning.md](tuning.md)) |
| Match per regola (top 10) | andamento delle 10 regole più attive | una regola che parte con un rilascio dell'applicazione indica un falso positivo |
| Disaccordi vs AWS default per sito e user_class | dove e per chi l'azione differisce da AWS | per esempio `BLOCK` contro `ALLOW` su `strict` è voluto; `ALLOW` contro `BLOCK` su un sito Odoo è un'eccezione da giustificare |
| Path delle regole in COUNT | i path su cui scattano le regole in COUNT | da qui nascono i prefissi delle label rule (`uri_path`) |
| Match per user_class | match per classe di utente | un `internal` con molti match è quasi sempre un falso positivo |

### WAF Request Explorer (`waf-explorer`)

Legge gli eventi grezzi. Filtri: **Sito**, **IP**, **Regola terminante** (nome esatto, per esempio
`NoUserAgent_HEADER`, o con il gruppo), **Azione**, **Request ID**.

- **Ultimi 500 eventi**: copia il `request_id` di una riga nel filtro *Request ID*.
- **Match della richiesta**: mostra tutte le regole che hanno matchato quella richiesta, comprese
  quelle in COUNT e quelle valutate dopo la regola terminante (`post_terminating = 1`), con la
  variabile e il valore. Il dettaglio completo, compreso il body, si ottiene con
  `wafctl logs show <request_id>`.
- **Paesi** / **ASN (top)**: provenienza dal GeoIP del centrale. `??` / ASN 0 sono IP privati o
  sconosciuti.

### WAF Nodes Health (`waf-nodes`)

| Pannello | Fonte | Cosa guardare |
|---|---|---|
| Heartbeat dei nodi | ClickHouse `waf.heartbeats` | `age_s` oltre 180 s → nodo silenzioso (alert); `config_rev` diversa tra i nodi → apply non uniforme |
| Richieste/s nginx | `nginx_http_requests_total` | carico per nodo |
| Connessioni attive nginx | `nginx_connections_active` | — |
| CPU occupata | `host_cpu_seconds_total` (idle) | CPU dell'host, non del container |
| Memoria disponibile | `host_memory_available_bytes` | — |
| Buffer Vector | `vector_buffer_size_bytes` | se cresce, il nodo non riesce a inoltrare al centrale (rete, centrale giù) |
| Errori componenti Vector | `vector_component_errors_total` | vuoto finché non c'è un errore |
| Query ClickHouse in corso | `ClickHouseMetrics_Query` | — |

### Modificare le dashboard

Il JSON in `deploy/grafana/dashboards/` è **generato**: non modificarlo a mano e non salvare
dall'interfaccia, perché le modifiche sono bloccate. Il flusso è:

1. modifica la tabella dei pannelli `deploy/grafana/panels.py` (titolo, tipo, SQL o PromQL,
   larghezza e altezza su griglia di 24 colonne);
2. rigenera e controlla con `make dashboards` (titoli unici, nessuna sovrapposizione, JSON
   aggiornato);
3. verifica tutte le query contro il Grafana del lab con `scripts/check-dashboards.sh`;
4. fai commit del JSON. Grafana lo ricarica da solo in circa 10 s.

Nel filtro sito, "All" vale `'__all__'` (già quotato). Grafana inserisce l'`allValue` così com'è,
senza applicare il formato `:singlequote`.

## Alert

Le regole sono generate da `central.yaml` in
`$WAF_CENTRAL_DIR/grafana/provisioning/alerting/rules.yaml`. Sono nella cartella **WAF**, gruppo
`waf`; vengono valutate ogni minuto e scattano dopo 2 minuti oltre soglia (`for: 2m`).

| Regola | Condizione (finestra) | Soglia in `central.yaml` | Default | Severità |
|---|---|---|---|---|
| WAF block spike | richieste BLOCK per sito negli ultimi 5 min | `alerts.block_spike_per_5m` | 500 | warning |
| WAF fail events | richieste FAIL (500 del WAF) per sito, 5 min | `alerts.fail_per_5m` (scatta a ≥ soglia) | 1 | critical |
| WAF vs AWS default disagreement | richieste con azione ≠ AWS default per sito, 5 min | `alerts.disagreement_per_5m` | 200 | warning |
| WAF node silent | secondi dall'ultimo heartbeat per nodo | `alerts.node_silent_min` × 60 | 3 min | critical |
| WAF ingest lag | secondi dall'ultimo evento per sito (siti attivi nelle ultime 24 h) | `alerts.ingest_lag_min` × 60 | 5 min | warning |

- **Ingest lag** scatta anche quando un sito non riceve traffico, per esempio un sito poco usato o il
  lab fermo; il messaggio lo dice. Guarda prima *node silent*: se i nodi sono vivi e il sito ha
  traffico, il problema è l'inoltro (buffer Vector, centrale). Sui siti con poco traffico alza
  `ingest_lag_min`.
- Le notifiche sono raggruppate per `alertname` e `site_id`: 30 s di attesa iniziale, poi un
  aggiornamento ogni 5 min se cambia qualcosa, e un promemoria ogni 4 h se l'alert resta attivo.
  Può capitare che un alert rientri e scatti di nuovo entro 5 minuti, prima che venga inviata la
  notifica di rientro. In quel caso non arriva una nuova notifica: per Alertmanager è lo stesso
  alert ancora attivo, già notificato, e ti verrà ricordato solo dopo 4 h. Per sapere se un picco
  è ancora in corso guarda lo stato in Grafana (Alerting → Alert rules), non solo le notifiche.
- Il messaggio ha titolo `[WAF] <regola>` e corpo `firing: N alert(s). site demo: 306 blocked
  requests in 5 min (threshold 20)`. Il tipo è `warning` quando l'alert scatta e `success` quando
  rientra.

Per cambiare le soglie modifica `central.yaml` ed esegui `wafctl apply` (oppure
`wafctl central render` e poi riavvia Grafana). Grafana viene riavviato solo se i file generati
sono cambiati. `wafctl validate` rifiuta le soglie minori di 1.

## Notifiche con apprise

Grafana invia al container `apprise` (`http://apprise:8000/notify/waf`, non pubblicato) e apprise
inoltra a tutti gli URL elencati in `$WAF_CONFIG_DIR/apprise-urls.txt`:

```text
# un URL apprise per riga; righe vuote e commenti ignorati
slack://TokenA/TokenB/TokenC/#waf-alerts
gchat://workspace/key/token
tgram://123456789:AAH-bot-token/-1001234567890
```

| Servizio | Formato | Documentazione |
|---|---|---|
| Slack (webhook) | `slack://TokenA/TokenB/TokenC/#canale` | <https://github.com/caronc/apprise/wiki/Notify_slack> |
| Google Chat | `gchat://workspace/key/token` (dall'URL del webhook dello spazio) | <https://github.com/caronc/apprise/wiki/Notify_googlechat> |
| Telegram | `tgram://bot_token/chat_id` | <https://github.com/caronc/apprise/wiki/Notify_telegram> |
| Altri (email, Teams, ntfy, …) | | <https://github.com/caronc/apprise/wiki> |

- Il file contiene token segreti: **escludilo da git** nel repo del nodo centrale (riga
  `apprise-urls.txt` nel `.gitignore`). Solo il file del lab è versionato, perché punta
  all'`alert-sink` locale e non contiene segreti.
- `wafctl apply` lo trasforma in `$WAF_CENTRAL_DIR/apprise/waf.yml`, con ogni URL etichettato
  `waf`. Se il file è vuoto o manca, `wafctl validate` avvisa: "no URLs, alerts will not be
  delivered".
- Per provare la consegna senza aspettare un alert, usa *Alerting → Contact points → apprise →
  Test* in Grafana. In alternativa usa l'API, come fa `tests/e2e/alerts.sh`.

## Lab

- `make lab-up` avvia anche Prometheus, Grafana, apprise e `alert-sink`, un piccolo server che
  stampa ogni notifica (profilo compose `test`, attivato da `COMPOSE_PROFILES=test` nel Makefile e in
  `scripts/lab-env.sh`).
- `lab/config/central.yaml` abbassa `block_spike_per_5m` a 20.

```bash
source scripts/lab-env.sh
tests/e2e/metrics.sh                 # target Prometheus up, metriche nginx/host per node_id
tests/e2e/grafana.sh                 # dashboard, datasource, utenti, query dei pannelli
tests/e2e/alerts.sh                  # regole sane, test del contact point, picco di blocchi → notifica
docker logs waf-alert-sink-1 | grep ALERT-SINK
```
