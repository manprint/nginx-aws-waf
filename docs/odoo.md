# Odoo dietro il WAF

Profili, eccezioni e flusso di tuning per Odoo Community 12, 14, 16 e 18. Tutti i profili
Odoo sono **aws-compatible** (D27): esportabili 1:1 su AWS WAF. Le uniche leve usate sono
`rule_action_overrides: <Rule>: count` e una regola custom con label che blocca fuori dai
percorsi Odoo previsti. Mai: gruppo disabilitato, `override_action: count` di gruppo,
scope-down che esclude `/web`, `path_overrides` (nginx-only).

## Lab

```sh
source scripts/lab-env.sh
make lab-up            # waf + echo + vector + pg12/13/15/16 + odoo12/14/16/18, DB "lab" (admin/admin)
make lab-legit         # flussi Playwright legittimi (tests/legit/README.md) → 0 blocchi
make test-odoo         # corpus "demo" rilanciato su shop12..18 con tests/odoo-exceptions.yaml
make lab-attack        # nuclei + nikto per sito (build/lab/)
make lab-matrix        # matrice del giorno → build/lab/matrix.md
scripts/lab-matrix.sh --sql legit.sql   # gate: stampa 0
make lab-down          # oppure: make lab-reset FORCE=1 (cancella i volumi)
```

| Sito | Odoo | Postgres | Realtime (porta 8072) |
|---|---|---|---|
| `shop12.lab.test` | 12 | 12 | `/longpolling` (`--longpolling-port`) |
| `shop14.lab.test` | 14 | 13 | `/longpolling` (`--longpolling-port`) |
| `shop16.lab.test` | 16 | 15 | `/websocket` (`--gevent-port`) |
| `shop18.lab.test` | 18 | 16 | `/websocket` (`--gevent-port`) |

Requisiti: circa 10 GB di RAM libera (4 × Odoo con `mem_limit 1500m`, misurati 330–450 MiB
ciascuno a riposo). Primo avvio: circa 3 minuti (creazione dei database 27–42 s per versione).

## Profili

`profiles/odoo-common.yaml` (estende `aws-default`) contiene tutto il tuning;
`odoo-12/14/16/18.yaml` estendono `odoo-common` senza modifiche (nessuna regola è servita a
una sola versione). Il ciclo di tuning della sotto-fase 2.5 è convergito alla prima iterazione:
flussi legittimi 0 blocchi, `make test-odoo` 48/48 su ogni sito.

| Regola AWS | Azione | Regola custom (blocca fuori dai percorsi) | Percorsi ammessi |
|---|---|---|---|
| `SizeRestrictions_BODY` | count | `OdooBodySizeOutsideRpc` | `/web/dataset/`, `/web/binary/`, `/mail/`, `/html_editor/`, `/web_editor/`, `/website/`, `/web/action/`, `/longpolling/`, `/websocket`, `/bus/`, `/web/webclient/` |
| `CrossSiteScripting_BODY` | count | `OdooXssBodyOutsideEditor` | `/web/dataset/`, `/mail/`, `/html_editor/`, `/web_editor/`, `/website/` |
| `GenericRFI_BODY` | count | `OdooRfiBodyOutsideRpc` | `/web/dataset/`, `/mail/`, `/html_editor/`, `/web_editor/`, `/website/` |

Perché, con le righe della matrice (`docs/lab-matrix-001.md`, solo richieste legit
`X-Waf-Test: <RUN_ID>-legit`, 26-11-2026):

| Sito | Regola | Azione configurata | Percorso | Match |
|---|---|---|---|---|
| shop12 / 14 / 16 | `SizeRestrictions_BODY` | COUNT | `/web/dataset/call_kw/…` | 18 ciascuno |
| shop18 | `SizeRestrictions_BODY` | COUNT | `/web/dataset/call_kw/…` | 15 |
| shop12 / 14 / 16 | `CrossSiteScripting_BODY` | COUNT | `/web/dataset/call_kw/…` | 6 ciascuno |
| shop18 | `CrossSiteScripting_BODY` | COUNT | `/web/dataset/call_kw/…` | 5 |

- `SizeRestrictions_BODY` (corpo > 8 KB): ogni `create`/`write` con HTML lungo e ogni
  allegato (`ir.attachment` con `datas` base64) passa da JSON-RPC. In `aws-default` sarebbero 403.
- `CrossSiteScripting_BODY`: i campi HTML (note, chatter `message_post`, editor del sito)
  contengono markup che il rilevatore XSS segnala; Odoo lo sanifica lato server.
- `GenericRFI_BODY`: preventivo. Un contenuto HTML con link a URL con indirizzo IP
  (`http://10.0.0.1/…`) viene segnalato; i flussi di lab non lo hanno attivato.
- Fuori dai percorsi ammessi le stesse richieste restano bloccate (403), con regola
  terminante `custom:<sito>/Odoo…` e la regola gestita in `matches`.
- Rischio accettato: dentro i percorsi ammessi XSS/RFI/size nel **corpo** non bloccano. Le
  regole su query string, URI, cookie e header restano in BLOCK (vedi sezione 2 della matrice).

## Eccezioni del corpus (`tests/odoo-exceptions.yaml`)

| Caso | Siti | Atteso | Motivo |
|---|---|---|---|
| `crs-size-body`, `crs-size-body-chunked` | tutti | 403 `OdooBodySizeOutsideRpc` | conteggiata, ribloccata fuori dai percorsi RPC |
| `crs-rfi-body` | tutti | 403 `OdooRfiBodyOutsideRpc` | idem |
| `crs-xss-body`, `crs-xss-multipart` | tutti | 403 `OdooXssBodyOutsideEditor` | idem |
| `clean-get` | tutti | 303 | redirect di Odoo verso `/web/login` |
| `clean-post-form` | tutti | 400 | Odoo rifiuta un POST senza `csrf_token` |
| `body-limit-8k` | 12/14: 302, 16/18: 400 | Default_Action | su `/web/dataset/` la dimensione è conteggiata; il payload oltre 8 KB non è ispezionato (come AWS) |

Nessuna eccezione trasforma un blocco in un passaggio su un percorso non Odoo.

## Realtime (long-polling e websocket)

Il campo `upstream.realtime` del sito genera una `location <path>` verso la porta 8072
(`/longpolling` per 12/14, `/websocket` per 16/18) con `Upgrade`/`Connection` e
`proxy_read_timeout 3600s`. Il resto va alla porta 8069 con `read_timeout_sec: 720`
(maggiore di `--limit-time-real=600`) e `max_body_size 100m` per gli allegati. Odoo gira con
`--proxy-mode`; il sito usa `client_ip: {source: xff}` (lab: proxy fidati `0.0.0.0/0`, solo
per il lab).

## Tuning di un nuovo modulo Odoo

Segue il flusso di [tuning.md](tuning.md):

1. Mettere il sito in `shadow` (o lasciare `odoo-NN` e osservare), esercitare il modulo.
2. `scripts/lab-matrix.sh` (o i dashboard) → sezione 4/2: per ogni blocco legittimo
   prendere `(sito, regola, percorso)`; `wafctl test request` e `wafctl explain <sito>` per
   capire la regola.
3. Regola già conteggiata con una custom `Odoo…`: aggiungere al regex negato il **prefisso
   letterale minimo** del percorso (mai `.*`).
4. Altrimenti: `rule_action_overrides: <Rule>: count` e una custom `Odoo<Rule>OutsideX` della
   stessa forma. In `odoo-common` se serve a tutte le versioni, altrimenti in `odoo-NN`.
5. `make test-odoo`: un attacco che ora passa su un percorso fuori dai prefissi è un bug; su
   un percorso ammesso → eccezione con `reason` (rischio accettato).
6. `make lab-legit` = 0 blocchi, `go test ./internal/config -run TestPRF1_` (aws-compatible).
