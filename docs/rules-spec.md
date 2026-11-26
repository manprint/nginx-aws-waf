# Specifica regole – simulazione web ACL "one-click" ALB

Fonte: `docs/aws/*.md` (fetch 2026-11-26). Dove AWS non pubblica il dettaglio (pattern proprietari)
la colonna **Impl.** indica l'approssimazione scelta. Legenda: ✅ fedele, ≈ approssimato, ⚠ stub.

## 1. Parametri globali (default AWS per ALB)

| Parametro | Default AWS | Fonte | Impl. ModSecurity/nginx |
|---|---|---|---|
| Default action web ACL | Allow | one-click | `SecDefaultAction` pass |
| Body inspection limit | 8 KB (8 192 B), opz. 16/32/48/64 KB | body-inspection-limit.md | `SecRequestBodyLimit 8192` + `SecRequestBodyLimitAction ProcessPartial` (parametrizzato `WAF_BODY_LIMIT`) |
| Oversize handling managed rules | Continue (ispeziona solo la parte entro il limite) | oversize-components.md | ProcessPartial ✅ |
| Header ispezionabili | primi 8 KB **o** primi 200 header | oversize-components.md | ≈ ispezione di tutti gli header (troncamento non emulato) |
| Cookie ispezionabili | primi 8 KB **o** primi 200 cookie | oversize-components.md | ≈ come sopra |
| Block response | `403 Forbidden`, body HTML default, header `Server: awselb/2.0` | block-response.md | `SecRuleEngine On` + `error_page 403` statico ≈ |
| WAF irraggiungibile | ALB risponde 500 (fail-open off) | alb-waf-integration.md | fuori scope |
| Ordine rule group | priority 0 IpReputation → 1 Common → 2 KnownBadInputs | ⚠ assunto, da verificare con `get-web-acl` | ordine file di include |
| Valutazione | regole in ordine; prima regola **Block** termina; **Count** aggiunge label e prosegue | rule-actions.md | tutte le regole in **phase:2** (così l'ordine AWS è rispettato anche fra regole header/body) |
| Label | `awswaf:managed:aws:<group>:<Rule>` aggiunta su match (anche Count) | labels.md | `tag:` + `setvar:tx.labels` |
| Override | per regola (Block→Count/Allow/…) o intero gruppo a Count | rule-group-override.md | `SecRuleUpdateActionById` / variabili env |
| IP sorgente | IP della connessione (no XFF nei managed group) | ip-rep.md | `REMOTE_ADDR`; modalità test opzionale `X-Forwarded-For` |

### Mappatura componenti AWS → variabili ModSecurity

| Suffisso AWS | Componente | Variabile ModSecurity |
|---|---|---|
| `_HEADER` | nomi + valori header | `REQUEST_HEADERS_NAMES\|REQUEST_HEADERS` |
| `_COOKIE` | valori cookie | `REQUEST_COOKIES` |
| `_QUERYSTRING` | query string grezza | `QUERY_STRING` |
| `_QUERYARGUMENTS` | valori di tutti i parametri query | `ARGS_GET` |
| `_URIPATH` | path senza query | `REQUEST_FILENAME` (verificare decoding vs `REQUEST_URI_RAW`) |
| `_BODY` | body grezzo entro limite | `REQUEST_BODY` (+ `t:urlDecodeUni` dove serve) |
| `_METHOD` | metodo | `REQUEST_METHOD` |

Trasformazioni AWS dei managed rule non pubbliche → si usano quelle CRS
(`t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,…` caso per caso).

## 2. Schema ID

| Range | Rule group |
|---|---|
| 1100000–1100099 | AWSManagedRulesAmazonIpReputationList |
| 1200000–1200099 | AWSManagedRulesCommonRuleSet |
| 1300000–1300099 | AWSManagedRulesKnownBadInputsRuleSet |
| 1900000–1900099 | motore (init, label, logging) |

## 3. AWSManagedRulesAmazonIpReputationList (WCU 25)

Label prefix: `awswaf:managed:aws:amazon-ip-list:`

| ID | Regola AWS | Azione | Condizione | Impl. |
|---|---|---|---|---|
| 1100010 | AWSManagedIPReputationList | Block | IP in lista reputazione | ≈ `@ipMatchFromFile` Spamhaus DROP+ET+Feodo + `custom-test.txt` |
| 1100020 | AWSManagedReconnaissanceList | Block | IP che fanno ricognizione | ≈ `@ipMatchFromFile` DShield+CINS |
| 1100030 | AWSManagedIPDDoSList | **Count** | IP DDoS | ⚠ lista vuota (nessun feed pubblico) |

## 4. AWSManagedRulesCommonRuleSet (WCU 700)

Label prefix: `awswaf:managed:aws:core-rule-set:`. Tutte **Block**.

| ID | Regola AWS | Condizione AWS | Impl. (base CRS 4.30) |
|---|---|---|---|
| 1200010 | NoUserAgent_HEADER | header `User-Agent` assente | ✅ `&REQUEST_HEADERS:User-Agent @eq 0` (come CRS 920320) |
| 1200020 | UserAgent_BadBots_HEADER | UA di scanner (es. `nessus`, `nmap`) | ≈ `@pmFromFile scanners-user-agents.data` (CRS 913100) |
| 1200030 | SizeRestrictions_QUERYSTRING | query string > 2 048 B | ✅ `QUERY_STRING` `t:length` `@gt 2048` |
| 1200040 | SizeRestrictions_Cookie_HEADER | header Cookie > 10 240 B | ✅ `REQUEST_HEADERS:Cookie` `t:length` `@gt 10240` |
| 1200050 | SizeRestrictions_BODY | body > 8 192 B | ✅ `REQUEST_HEADERS:Content-Length @gt 8192`; ≈ chunked |
| 1200060 | SizeRestrictions_URIPATH | path > 1 024 B | ✅ path `t:length` `@gt 1024` |
| 1200070 | EC2MetaDataSSRF_BODY | metadata EC2 nel body | ≈ `@pmFromFile ec2-metadata.data` (sottoinsieme AWS di CRS `ssrf.data`, 934110) |
| 1200080 | EC2MetaDataSSRF_COOKIE | idem nei cookie | ≈ idem |
| 1200090 | EC2MetaDataSSRF_URIPATH | idem nel path | ≈ idem |
| 1200100 | EC2MetaDataSSRF_QUERYARGUMENTS | idem nei parametri query | ≈ idem |
| 1200110 | GenericLFI_QUERYARGUMENTS | LFI / `../../` | ≈ CRS 930100 + 930110 + 930120 (`lfi-os-files.data`) |
| 1200120 | GenericLFI_URIPATH | idem nel path | ≈ idem |
| 1200130 | GenericLFI_BODY | idem nel body | ≈ idem |
| 1200140 | RestrictedExtensions_URIPATH | estensioni di sistema (es. `.log`, `.ini`) | ≈ CRS 920440 con `tx.restricted_extensions` CRS |
| 1200150 | RestrictedExtensions_QUERYARGUMENTS | idem nei valori query | ≈ stessa lista, `@rx \.(ext)$` su `ARGS_GET` |
| 1200160 | GenericRFI_QUERYARGUMENTS | URL `http/https/ftp/ftps/file://<IPv4>` | ≈ CRS 931100 ristretto a IPv4 |
| 1200170 | GenericRFI_BODY | idem nel body | ≈ idem |
| 1200180 | GenericRFI_URIPATH | idem nel path | ≈ idem |
| 1200190 | CrossSiteScripting_COOKIE | XSS (statement XSS AWS) | ≈ `@detectXSS` libinjection (CRS 941100) + 941110 |
| 1200200 | CrossSiteScripting_QUERYARGUMENTS | idem | ≈ idem |
| 1200210 | CrossSiteScripting_BODY | idem | ≈ idem |
| 1200220 | CrossSiteScripting_URIPATH | idem | ≈ idem |

Nota: il CommonRuleSet **non** include SQLi (`AWSManagedRulesSQLiRuleSet` è un gruppo separato, non attivo di default).

## 5. AWSManagedRulesKnownBadInputsRuleSet (WCU 200)

Label prefix: `awswaf:managed:aws:known-bad-inputs:`

| ID | Regola AWS | Azione | Condizione AWS | Impl. |
|---|---|---|---|---|
| 1300010 | JavaDeserializationRCE_HEADER | Block | RCE Java, Spring4Shell/Cloud Function (CVE-2022-22963/22965) | ≈ CRS 944100/944110/944130 + `class.module.classLoader`, `spring.cloud.function.routing-expression`, `java.lang.Runtime` |
| 1300020 | JavaDeserializationRCE_BODY | Block | idem | ≈ idem |
| 1300030 | JavaDeserializationRCE_URIPATH | Block | idem | ≈ idem |
| 1300040 | JavaDeserializationRCE_QUERYSTRING | Block | idem | ≈ idem |
| 1300050 | Host_localhost_HEADER | Block | Host indica localhost | ✅ `REQUEST_HEADERS:Host` `^(localhost\|127\.\d+\.\d+\.\d+\|\[?::1\]?)(:\d+)?$` |
| 1300060 | PROPFIND_METHOD | Block | metodo `PROPFIND` | ✅ `REQUEST_METHOD @streq PROPFIND` |
| 1300070 | ExploitablePaths_URIPATH | Block | path sfruttabili (es. `web-inf`) | ≈ `(?i)/(web-inf\|meta-inf)(/\|$)` |
| 1300080 | Log4JRCE_HEADER | Block | `${jndi:…}` (CVE-2021-44228/45046/45105) | ≈ CRS 944150/944151 |
| 1300090 | Log4JRCE_QUERYSTRING | Block | idem | ≈ idem |
| 1300100 | Log4JRCE_BODY | Block | idem | ≈ idem |
| 1300110 | Log4JRCE_URIPATH | Block | idem | ≈ idem |
| 1300120 | ReactJSRCE_BODY | Block | React2Shell CVE-2025-55182 | ≈ indicatori pubblici: header `Next-Action` + body con `__proto__` / `constructor:constructor` |
| 1300130 | ApacheMod_HTTP2 | **Count** | CVE-2026-119618 | ⚠ stub (pattern non noti) |
| 1300140 | Java4Shell_BODY | **Count** | CVE-2026-114938 | ⚠ stub |
| 1300150 | Java4Shell_QUERYARGUMENTS | **Count** | idem | ⚠ stub |
| 1300160 | Java4Shell_HEADER | **Count** | idem | ⚠ stub |
| 1300170 | Java4Shell_AUTHORIZATION_HEADER | **Count** | idem | ⚠ stub |
| 1300180 | Ruby2Shell_METHODOVERRIDE_HEADER | **Count** | CVE-2026-132825 | ⚠ stub |
| 1300190 | Ruby2Shell_MethodOverride_BODY | **Count** | idem | ⚠ stub |
| 1300200 | Ruby2Shell_MULTIPARTMETHOD | **Count** | idem | ⚠ stub |

Le regole Count non cambiano l'esito (solo label/log): gli stub non alterano il comportamento Allow/Block.

## 6. Avvertenze per i test

- **Host_localhost_HEADER blocca `curl http://localhost:8080`**: è il comportamento AWS reale. Nei test usare un host
  come `app.localtest.me` o `-H 'Host: example.com'`.
- **NoUserAgent_HEADER**: `curl` invia sempre UA; per provarlo usare `-A ''` / `-H 'User-Agent:'`.
- IP reputation: dietro Docker `REMOTE_ADDR` è il gateway della bridge → usare la modalità test XFF con `203.0.113.x`.

## 7. Punti aperti

1. Verificare priority e versione dei rule group nella web ACL one-click reale (`aws wafv2 get-web-acl`, serve MFA).
2. Scaricare `describe-managed-rule-group` per confermare nomi regole e versione statica corrente.
3. Formato log: emulare i campi AWS (`terminatingRuleId`, `ruleGroupList`, `labels`, `httpRequest`) da audit log JSON ModSecurity.
4. Variabile path: `REQUEST_FILENAME` (decodificato) vs path grezzo – scegliere in base ai test.
