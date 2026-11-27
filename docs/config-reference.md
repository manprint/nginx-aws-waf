# Riferimento configurazione

La configurazione di un nodo è una directory (un repo git per nodo, `$WAF_CONFIG_DIR`):

```
node.yaml            # il nodo
sites/<site_id>.yaml # un file per sito
profiles/<nome>.yaml # profili locali (opzionali; quelli di prodotto sono in $WAF_HOME/profiles)
pages/<file>.html    # pagine di blocco personalizzate (opzionali)
state/bypass.yaml    # scritto da `wafctl bypass` (non modificare a mano)
```

`wafctl validate` controlla tutto (exit 2 con errori `file: chiave: messaggio`) e stampa per ogni
sito la riga di compatibilità: **aws-compatible** (riproducibile 1:1 su AWS WAF, esportabile con
`wafctl export-aws`) oppure **nginx-only (motivi)**.

Colonna **Compat**: `aws` = la chiave esiste anche in AWS WAF; `nginx-only` = il valore indicato
rende il sito non riproducibile su AWS; `—` = non influisce (infrastruttura del nodo).

## node.yaml

| Chiave | Tipo | Default | Compat | Note |
|---|---|---|---|---|
| `version` | int | — (obbligatorio, 1) | — | |
| `node_id` | string | — (obbligatorio) | — | finisce in ogni evento (`node_id`) |
| `role` | `node` \| `central` \| `all-in-one` | `node` | — | |
| `network` | `host` \| `bridge` | `host` | — | `host` in produzione, `bridge` nel lab |
| `listen.http` / `listen.https` | int | 80/443 (host), 8080/8443 (bridge) | — | |
| `listen.ipv6` | bool | `true` | — | aggiunge `listen [::]:<porta>` |
| `workers` | int | 0 = `auto` | — | `worker_processes` di nginx |
| `geoip.enabled` | bool | `false` | — | richiede le mmdb GeoLite2 in `$WAF_DATA_DIR/geoip` |
| `audit.scope` | `all` \| `relevant` | `all` | `relevant` = nginx-only | `relevant`: solo transazioni con match finiscono nell'audit log |
| `default_site` | site_id | "" | — | vuoto: Host sconosciuto → 444 (connessione chiusa) |
| `central.address` / `ingest_port` / `pki_port` | string/int | "", 6000, 6001 | — | fase 4–5 (inoltro mTLS) |
| `retention.raw_days` / `log_hours` | int | 7 / 24 | — | usati da `wafctl logs rotate` |
| `lab.enabled` | bool | `false` | — | abilita `trusted_proxies: 0.0.0.0/0` (solo lab) |

Esempio (lab): `lab/config/node.yaml`.

## sites/&lt;site_id&gt;.yaml — parte nginx

| Chiave | Tipo | Default | Compat | Note |
|---|---|---|---|---|
| `version` | int | — (1) | — | |
| `site_id` | `^[a-z0-9][a-z0-9_-]{0,31}$` | — | — | deve coincidere col nome file |
| `server_names` | lista | — | — | nomi `^[a-z0-9*.-]+$` (no IPv6 tra parentesi) |
| `app` | `odoo` \| `wordpress` \| `generic` | — | — | `odoo` aggiunge la location realtime; `odoo` e `wordpress` classificano le richieste (`user_class`: backend, api, static, website) |
| `profile` | nome | `aws-default` | — | catena `extends` risolta root → foglia |
| `upstream.servers` | lista `host:porta` | — | — | |
| `upstream.realtime.path` / `.servers` | string / lista | — | — | Odoo: `/longpolling` (12, 14) o `/websocket` (16, 18), porta 8072 |
| `upstream.tls` | bool | `false` | — | HTTPS verso il backend |
| `upstream.max_body_size` | dimensione nginx | `10m` | — | `client_max_body_size` (diverso dal limite di ispezione) |
| `upstream.read_timeout_sec` | int | 60 | — | |
| `tls.mode` | `off` \| `on` \| `redirect` | `off` | — | `redirect`: HTTP → 301 HTTPS |
| `tls.cert` / `tls.key` | file | `fullchain.pem` / `privkey.pem` | — | in `$WAF_DATA_DIR/certs/<site_id>/`, mai in git |

## Impostazioni WAF (profili e siti)

Le stesse chiavi valgono in un profilo e in un sito; il sito vince sul profilo, il profilo figlio sul
padre. `rule_groups` e `custom_rules` si fondono per nome (stesso nome = sostituito), `path_overrides` si sommano.

| Chiave | Tipo | Default | Compat | Note |
|---|---|---|---|---|
| `mode` | `enforce` \| `count` | `enforce` | aws | `count`: nessun blocco, tutto loggato (shadow). Un bypass attivo forza `count` |
| `default_action` | `allow` \| `block` | `allow` | aws | azione della web ACL se nessuna regola termina |
| `body_limit` | int byte | 8192 | 8192/16384/32768/49152/65536 = aws; altri fino a 1 MiB = nginx-only | limite di ispezione del body (D8) |
| `client_ip.source` | `remote_addr` \| `xff` | `remote_addr` | `xff` = nginx-only | `xff` usa `X-Forwarded-For` (realip) |
| `client_ip.trusted_proxies` | lista CIDR | [] | — | obbligatoria con `xff` |
| `fail.pcre_limit` | `closed` \| `block` \| `open` | `closed` | `block` = nginx-only | `closed` = 500 (come AWS se il WAF fallisce), `block` = 403, `open` = prosegue |
| `fail.body_error` | `closed` \| `block` \| `open` | `open` | `closed`/`block` = nginx-only | errore di parsing del body |
| `block_page` | `aws` \| file in `pages/` | `aws` | diverso da `aws` = nginx-only | corpo della risposta 403 |
| `rule_groups[]` | lista | i 3 gruppi one-click abilitati | aws | vedi sotto |
| `custom_rules[]` | lista | [] | aws | vedi sotto |
| `disable_custom_rules` | lista di nomi | [] | aws | disattiva regole ereditate da un profilo |
| `rate_limit` | oggetto | nessuno | aws | `limit` ≥ 10, `window_sec` ∈ {60,120,300,600}, `action` `block`\|`count` |
| `geo_block` | oggetto | nessuno | aws | `countries` ISO-3166, `action` `block`\|`count`; richiede `geoip.enabled` |
| `path_overrides[]` | lista | [] | nginx-only | `{path_prefix, rules: {<Regola>: block\|count\|allow}}` |

### rule_groups[]

| Chiave | Tipo | Note |
|---|---|---|
| `name` | nome AWS del gruppo | `AWSManagedRulesAmazonIpReputationList`, `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`, opzionali `AWSManagedRulesSQLiRuleSet`, `AWSManagedRulesAnonymousIpList`, `AWSManagedRulesAdminProtectionRuleSet`, `AWSManagedRulesLinuxRuleSet`, `AWSManagedRulesUnixRuleSet`, `AWSManagedRulesWindowsRuleSet`, `AWSManagedRulesPHPRuleSet`, `AWSManagedRulesWordPressRuleSet` (vedi `docs/rules-spec.md` §5b) |
| `enabled` | bool | i gruppi opzionali partono disabilitati; `false` disattiva un gruppo abilitato da un profilo padre |
| `override_action` | `none` \| `count` | `count` = tutto il gruppo in Count (come AWS) |
| `rule_action_overrides` | mappa `Regola: block\|count\|allow` | override per regola (come AWS `RuleActionOverrides`) |
| `scope_down` | match | il gruppo valuta solo le richieste che soddisfano il match |

### custom_rules[] e match

| Chiave | Tipo | Note |
|---|---|---|
| `name` | string | univoco nel sito |
| `slot` | `start` \| `after:<gruppo abilitato>` | posizione nella valutazione (priorità AWS) |
| `action` | `block` \| `allow` \| `count` | |
| `match.all[]` | lista di condizioni (AND, max 6) | ogni condizione ha esattamente un tipo, più `negate: true` opzionale |

Tipi di condizione: `label` (label completa, es. `awswaf:managed:aws:core-rule-set:SizeRestrictions_Body`),
`label_namespace`, `uri_path` / `header` (con `name`) / `query_arg` (con `name`) con uno fra
`exact`, `starts_with`, `contains`, `regex` e `transform` ⊆ {`urlDecodeUni`, `lowercase`},
`method` (lista), `ip_set` (lista CIDR), `geo` (lista paesi), `size`
(`component` ∈ `body|query_string|uri_path|cookie|header:<Nome>`, `op` ∈ `gt|ge|lt|le|eq`, `value`).
I valori non possono contenere virgolette o a capo.

Esempio (da `lab/config/sites/tuned.yaml`):

```yaml
version: 1
site_id: tuned
server_names: [tuned.lab.test]
app: generic
upstream: {servers: ["echo:8081"]}
body_limit: 16384
fail: {pcre_limit: open}
rule_groups:
  - name: AWSManagedRulesCommonRuleSet
    rule_action_overrides: {SizeRestrictions_BODY: count}
  - name: AWSManagedRulesKnownBadInputsRuleSet
    scope_down: {all: [{uri_path: {starts_with: /static-ok/}, negate: true}]}
custom_rules:
  - name: BlockLargeBodyOutsideRpc
    slot: after:AWSManagedRulesCommonRuleSet
    action: block
    match:
      all:
        - {label: "awswaf:managed:aws:core-rule-set:SizeRestrictions_Body"}
        - {uri_path: {starts_with: /web/dataset/}, negate: true}
path_overrides:
  - {path_prefix: /files/, rules: {RestrictedExtensions_URIPATH: count}}
```

## Profili di prodotto (`profiles/`)

| Profilo | Contenuto |
|---|---|
| `aws-default` | la web ACL one-click: IpReputation → CommonRuleSet → KnownBadInputs, azioni default AWS |
| `shadow` | `aws-default` con `mode: count` (primo deploy) |
| `strict` | `aws-default` + SQLi + AnonymousIp |
| `web-common` | qualunque sito su Linux: `aws-default` + SQLi + Linux + Unix; blocca file riservati (`.env`, `.git`, chiavi, backup, `composer.json`, `docker-compose.yml`), percorsi cercati dagli scanner (phpunit, actuator, `_ignition`, `cgi-bin`, router/VPN), metodi TRACE/TRACK/DEBUG/CONNECT |
| `php` | `web-common` + PHP; blocca webshell/`phpinfo.php` e phpMyAdmin/Adminer (Laravel, Symfony, Drupal, Joomla, PrestaShop, Magento) |
| `wordpress` | `php` + WordPress; regole sul body in Count negli endpoint dell'editor (`wp-admin/post.php`, `/wp-json/wp/v2/`…) e Block altrove (regole `WordPress*OutsideEditor`); blocca enumerazione utenti e file di versione. Con `app: wordpress` |
| `static` | `web-common`; solo GET/HEAD/OPTIONS, nessuno script lato server (`.php`, `.asp`, `.jsp`…) |
| `api` | `web-common`; NoUserAgent e SizeRestrictions_BODY in Count (client non-browser, JSON grandi) |
| `aspnet` | `web-common` con Windows al posto di Linux/Unix; SizeRestrictions_BODY in Count (ViewState) |
| `odoo-common`, `odoo-12/14/16/18` | Odoo (vedi `docs/odoo.md`) |

Ogni regola di un profilo si regola nel file del sito: `disable_custom_rules: [BlockDbAdminTools]`,
una custom rule con lo stesso nome (es. `action: count`) la sostituisce, `rule_groups[].enabled: false`
spegne un gruppo, `rule_action_overrides` cambia l'azione di una singola regola AWS. Esempio:

```yaml
# sites/blog.yaml
site_id: blog
server_names: [blog.example.com]
app: wordpress
upstream: {servers: ["wordpress:80"]}
profile: wordpress
rule_groups:
  - name: AWSManagedRulesWordPressRuleSet
    rule_action_overrides: {WordPressExploitablePaths_URIPATH: count}   # xmlrpc.php serve a Jetpack
disable_custom_rules: [WordPressBlockFingerprintFiles]
```
