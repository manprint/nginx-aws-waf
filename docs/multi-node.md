# Multi-nodo: PKI, mTLS, enrollment, installazione

Questo documento descrive l'installazione con più nodi WAF (circa 20) che inviano eventi, match,
heartbeat e metriche a un nodo **centrale** (ClickHouse, Grafana, Prometheus, alert). Il canale
nodo → centrale è sempre **mTLS**, con certificati emessi da una CA propria (self-signed) e
revocabili tramite CRL.

## Topologia

```
  nodo web-1 ─┐  Vector (sink vector, TLS client cert)
  nodo web-2 ─┼──── tcp/6000 ───► centrale: ingress (nginx stream, mTLS + CRL) ─► vector-central ─► ClickHouse
  nodo web-N ─┘
        └──────── tcp/6001 ───► centrale: wafctl pki serve (enroll/renew, systemd, fuori da Docker)
```

Il centrale può stare in tre posti:

- **on-premise**: i nodi EC2 lo raggiungono via VPN/Direct Connect o via IP pubblico. In questo
  caso le porte 6000/6001 vanno aperte solo agli IP dei nodi.
- **AWS**: un'istanza `central` nella stessa VPC (vedi [Terraform](#terraform)). I security group
  lasciano 6000/6001 solo a `node_cidrs`.
- **tailnet (Tailscale)**: centrale e nodi nella stessa tailnet. Si usa il nome MagicDNS o l'IP
  100.x del centrale (vedi [Tailscale](#tailscale)).

Ruoli (`node.yaml role`):

| Ruolo | Contenuto |
|---|---|
| `node` | nginx+ModSecurity, Vector del nodo; inoltra via mTLS a `central.address:ingest_port` |
| `central` | ClickHouse, vector-central, ingress mTLS, Prometheus, Grafana, apprise, `pki serve` |
| `all-in-one` | entrambi sulla stessa macchina. Il salto locale nodo → centrale è in chiaro sulla rete locale (bridge) o su `127.0.0.1:6100` (host). I nodi remoti passano comunque dall'ingress mTLS |

## Porte e firewall

| Porta | Dove | Da chi | Cosa |
|---|---|---|---|
| 80, 443 | nodi | Internet | traffico web protetto dal WAF |
| 6000/tcp | centrale | solo nodi | ingest mTLS (`ingress.bind:ingress.ingest_port`) |
| 6001/tcp | centrale | solo nodi (e l'admin, durante l'enrollment) | API PKI: `GET /ca`, `POST /enroll`, `POST /renew`, `GET /healthz` |
| 3000 | centrale | `127.0.0.1` (tunnel SSH) o tailnet | Grafana ([dashboards-alerts.md](dashboards-alerts.md)) |
| 8123 | centrale | solo `127.0.0.1` | ClickHouse HTTP (`wafctl logs/stats/report`) |

L'ingress rifiuta ogni client senza un certificato valido della CA (`ssl_verify_client on`).
Il firewall resta comunque necessario: riduce la superficie esposta. L'API PKI ha un rate limit di
10 richieste al minuto per IP.

## PKI

La PKI vive solo sul centrale, in `$WAF_PKI_DIR` (default `$WAF_CONFIG_DIR/pki`):

| File | Contenuto | Permessi | In git |
|---|---|---|---|
| `ca.pem` | certificato della CA (ECDSA P-256, 10 anni) | 0644 | sì |
| `private/ca.key` | chiave della CA | 0600 (dir 0700) | **mai** |
| `issued/<serial>.pem` | certificati emessi | 0644 | sì |
| `index.json` | serial, CN, tipo, scadenza, revoca, rinnovo; numero della CRL | 0600 | sì |
| `crl.pem` | CRL (valida 7 giorni) | 0644 | sì |
| `tokens.json` | token di enrollment (solo sha256) | 0600 | **mai** |

La chiave della CA non entra mai in un container. L'ingress riceve in
`$WAF_CENTRAL_DIR/ingress/certs/` solo `ingress.pem`, `ingress.key`, `ca.pem` e `crl.pem`.
`wafctl pki serve` gira come servizio systemd sull'host.

### Inizializzazione (centrale)

```sh
wafctl pki init --name prod          # stampa ca_sha256=...
$EDITOR $WAF_CONFIG_DIR/central.yaml # ingress.server_names / server_ips: i nomi che i nodi usano
wafctl apply                         # genera nginx.conf e il cert server dell'ingress, avvia i servizi
systemctl enable --now wafctl-pki.service wafctl-pki-crl.timer
```

`ingress.server_names` e `ingress.server_ips` finiscono nei SAN del certificato server
dell'ingress. I nodi verificano l'hostname (`verify_hostname: true`), quindi
`node.yaml central.address` deve essere uno di questi valori. Se li cambi, `wafctl apply`
riemette il certificato.

### Enrollment di un nodo

Sul **centrale**:

```sh
wafctl pki token --cn web-7 --ttl 24h
# token=Q2x...   (monouso, legato al CN, scade dopo il ttl, max 720h)
# ca_sha256=ffb1afe8...
```

Sul **nodo** (`node_id: web-7`, `central.address` impostato):

```sh
wafctl node enroll --token Q2x... --ca-sha256 ffb1afe8...
```

Passi di `node enroll`:

1. Scarica la CA da `https://<central>:6001/ca`. La confronta con `--ca-sha256` (pinning): se non
   corrisponde si ferma, senza scrivere né inviare nulla.
2. Genera localmente la chiave (`node.key` 0600; non lascia mai il nodo) e una CSR con CN =
   `node_id`.
3. Invia `POST /enroll` verificando il server con la CA appena fissata.
4. Scrive `$WAF_DATA_DIR/certs/_node/{node.pem,node.key,ca.pem}` e riavvia Vector.

Un token già usato, scaduto o per un altro CN riceve 403.

### Rinnovo

I certificati dei nodi valgono 90 giorni. Il timer `wafctl-node-renew.timer` (giornaliero, con
ritardo casuale fino a 1 h) esegue `wafctl node renew`. Il comando non fa nulla finché mancano più
di 30 giorni alla scadenza; dopo genera una nuova chiave e chiede `POST /renew` autenticandosi con
il certificato attuale. Il vecchio serial resta valido fino alla scadenza naturale (`pki list` lo
mostra `renewed`) e non viene revocato.

```sh
wafctl node renew            # sul nodo; --force per rinnovare subito
wafctl pki list              # sul centrale: SERIAL CN KIND NOT_AFTER STATUS
```

### Revoca

```sh
wafctl pki revoke web-7      # tutti i certificati non revocati del CN (oppure un serial)
```

La revoca rigenera la CRL, la copia nell'ingress e lo ricarica. Le sessioni già aperte vengono
chiuse entro 10 s (`worker_shutdown_timeout`), e al ricollegamento il nodo viene rifiutato con
`certificate revoked`. Gli eventi del nodo revocato restano nel suo buffer su disco di Vector
(fino a 2 GiB) e nei file `raw/` locali. Se il nodo viene ri-autorizzato (nuovo token + enroll),
il buffer viene consegnato.

### CRL: attenzione alla scadenza

> **Se la CRL scade (`next_update` passato), nginx rifiuta TUTTI i nodi.**

La CRL vale 7 giorni e viene rigenerata ogni giorno da `wafctl-pki-crl.timer` (`wafctl pki crl`).
Verifica che il timer sia attivo e controlla la data della CRL:

```sh
systemctl list-timers wafctl-pki-crl.timer
openssl crl -in $WAF_PKI_DIR/crl.pem -noout -nextupdate
```

Se il centrale è rimasto spento per più di 7 giorni, all'avvio esegui subito `wafctl pki crl`.

Una CRL firmata da un'altra CA ha lo stesso effetto: nginx rifiuta tutti i nodi con
`FAILED:unable to get certificate CRL`. Per questo `wafctl pki revoke|crl` pubblica la CRL
sull'ingress solo se è firmata dalla CA dell'ingress (`ingress/certs/ca.pem`). Se `WAF_PKI_DIR`
punta a un'altra CA il comando termina con
`crl: issuer "…" is not the ingress CA "…": refusing to publish` e l'ingress non viene toccato.

### Backup della CA

Senza `private/ca.key` non si possono emettere né rinnovare certificati, né aggiornare la CRL.
Quando la CRL scade, tutti i nodi smettono di inviare. Quindi:

- dopo `pki init`, copia `$WAF_PKI_DIR` (compresi `private/` e `index.json`) su un supporto
  **offline** cifrato (es. `tar czf - pki | gpg -c > pki-backup.tgz.gpg`);
- ripeti la copia dopo ogni modifica importante, oppure conserva almeno `private/ca.key` e
  `ca.pem`. Con questi due file si ricostruisce tutto: i nodi esistenti restano validi;
- non mettere `private/` o `tokens.json` in git: il `.gitignore` generato da `node bootstrap` li
  esclude.

## Installazione di un nodo

Sul PC di build:

```sh
make release VERSION=0.5.0           # build/nginx-aws-waf-0.5.0.tar.gz
```

Sul server (Ubuntu 22.04/24.04, come root, con Docker e il plugin compose già installati):

```sh
tar xzf nginx-aws-waf-0.5.0.tar.gz
nginx-aws-waf-0.5.0/scripts/install-node.sh          # → /opt/nginx-aws-waf, /usr/local/bin/wafctl
wafctl node bootstrap --node-id web-7 --role node --central central.example.com --install-systemd
```

`node bootstrap` esegue questi passi:

1. Crea `$WAF_CONFIG_DIR` (default `/etc/waf-node`) come repository git con `.gitignore`,
   `node.yaml`, `sites/` e `profiles/`; per i ruoli centrali anche `central.yaml`.
2. Genera `secrets.env` (0600) e crea le directory in `$WAF_DATA_DIR` (default `/srv/waf`).
3. Con `--install-systemd`, installa i timer del ruolo:
   - node: bypass-expire, logs, node-renew, lists;
   - central: pki-crl, pki;
   - all-in-one: tutti tranne node-renew (compreso lists).

   `wafctl-geoip.timer` va abilitato a mano, perché serve un account MaxMind ([operations.md](operations.md#geoip)).
4. Fa il primo commit `bootstrap <id>`.

Poi:

1. Scarica le liste IP con `wafctl lists update --no-apply`. Le installa in `$WAF_DATA_DIR/lists/`.
2. Aggiungi i siti in `sites/`, poi esegui `wafctl validate && wafctl apply`.
3. Esegui l'enrollment (vedi sopra).
4. Fai commit delle modifiche.

## Tailscale

Con centrale e nodi nella stessa tailnet:

- in `central.yaml`, metti il nome MagicDNS e/o l'IP tailnet del centrale:
  ```yaml
  ingress: {bind: "100.64.0.10", ingest_port: 6000, pki_port: 6001,
            server_names: [waf-central.tail1234.ts.net], server_ips: [100.64.0.10]}
  grafana: {bind: "100.64.0.10:3000", root_url: "http://waf-central.tail1234.ts.net:3000/"}
  ```
- sui nodi, `node.yaml central.address: waf-central.tail1234.ts.net` (oppure l'IP 100.x);
- `ingress.bind` sull'IP tailnet espone 6000 solo sulla tailnet. Le ACL di Tailscale possono
  restringere ulteriormente l'accesso ai soli nodi WAF.

L'mTLS resta attivo anche dentro la tailnet: protegge dai dispositivi della tailnet che non sono
nodi WAF.

## Terraform

`deploy/terraform/` è uno scheletro, validato con `make tf-validate` e mai applicato da questo
progetto. Contiene:

- i security group (80/443 dal mondo per i nodi; 6000/6001 solo da `node_cidrs` per il centrale);
- un'istanza per ogni elemento di `var.nodes`;
- uno user-data che installa Docker e la release ed esegue `node bootstrap --install-systemd`.

L'enrollment resta manuale, perché richiede un token monouso generato sul centrale. Dettagli in
[deploy/terraform/README.md](../deploy/terraform/README.md).

## Lab con due nodi

`tests/e2e/multinode.sh` avvia un secondo nodo con queste caratteristiche:

- progetto compose `waf2`;
- configurazione `lab/config-node2/` e dati `.run2/`;
- porte 18080/18443.

Il nodo raggiunge l'ingress del lab come `central.lab.test` attraverso l'host, cioè come farebbe
un nodo remoto. Lo script verifica, nell'ordine:

1. inoltro mTLS;
2. enrollment con token;
3. riuso del token → 403;
4. rinnovo;
5. revoca → nessun evento.

Per fermare il secondo nodo:

```sh
docker compose -p waf2 down
```
