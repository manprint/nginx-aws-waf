# Specifica regole – simulazione web ACL "one-click" ALB

Fonte: `docs/aws/*.md` (fetch 2026-11-26). Dove AWS non pubblica il dettaglio (pattern proprietari)
la colonna **Impl.** indica l'approssimazione scelta. Legenda: ✅ fedele, ≈ approssimato, ⚠ stub.

## 1. Parametri globali (default AWS per ALB)

| Parametro | Default AWS | Fonte | Impl. ModSecurity/nginx |
|---|---|---|---|
| Default action web ACL | Allow | one-click | `SecDefaultAction` pass |
| Body inspection limit | 8 KB (8 192 B); per ALB configurabile solo 8/16/32/48/64 KB | body-inspection-limit.md | `SecRequestBodyLimit` = `body_limit` del sito + `ProcessPartial`. Valori 8192/16384/32768/49152/65536 = aws-compatible, altri (fino a 1 MiB) = nginx-only (D8). `SizeRestrictions_BODY` resta fisso a > 8192 come in AWS |
| Oversize handling managed rules | Continue (ispeziona solo la parte entro il limite) | oversize-components.md | ProcessPartial ✅ |
| Header ispezionabili | primi 8 KB **o** primi 200 header | oversize-components.md | ≈ ispezione di tutti gli header (troncamento non emulato) |
| Cookie ispezionabili | primi 8 KB **o** primi 200 cookie | oversize-components.md | ≈ come sopra |
| Block response | `403 Forbidden`, body HTML default, header `Server: awselb/2.0` | block-response.md | `SecRuleEngine On` + `error_page 403` statico ≈ |
| WAF irraggiungibile | ALB risponde 500 (fail-open off) | alb-waf-integration.md | errore interno del motore → 500; limite PCRE / errore body → `fail` per sito (default closed = 500, `open` = prosegue) |
| Ordine rule group | priority 0 IpReputation → 1 Common → 2 KnownBadInputs | ⚠ assunto, da verificare con `get-web-acl` | ordine file di include |
| Valutazione | regole in ordine; prima regola **Block** termina; **Count** aggiunge label e prosegue | rule-actions.md | tutte le regole in **phase:2** (così l'ordine AWS è rispettato anche fra regole header/body) |
| Label | `awswaf:managed:aws:<group>:<Rule>` aggiunta su match (anche Count) | labels.md | `tag:` + `setvar:tx.labels` |
| Override | per regola (Block→Count/Allow/…) o intero gruppo a Count | rule-group-override.md | variabili TX per sito (`rule_action_overrides`, `override_action`) renderizzate da `wafctl` |
| IP sorgente | IP della connessione (no XFF nei managed group) | ip-rep.md | `REMOTE_ADDR`; modalità test opzionale `X-Forwarded-For` |

### Mappatura componenti AWS → variabili ModSecurity

| Suffisso AWS | Componente | Variabile ModSecurity |
|---|---|---|
| `_HEADER` | nomi + valori header | `REQUEST_HEADERS_NAMES\|REQUEST_HEADERS` |
| `_COOKIE` | valori cookie | `REQUEST_COOKIES` |
| `_QUERYSTRING` | query string grezza | `QUERY_STRING` |
| `_QUERYARGUMENTS` | valori di tutti i parametri query | `ARGS_GET` |
| `_URIPATH` | path senza query | `TX:raw_path` = path grezzo da `REQUEST_URI_RAW` (D7) |
| `_BODY` | body grezzo entro limite | `REQUEST_BODY` (+ `t:urlDecodeUni` dove serve) |
| `_METHOD` | metodo | `REQUEST_METHOD` |

Trasformazioni AWS dei managed rule non pubbliche → si usano quelle CRS
(`t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,…` caso per caso).

## 2. Schema ID

Mappa definitiva (D23, piano 001). `siteIdx` = indice del sito nella lista ordinata dei `site_id`
(max 100 siti per nodo); `ruleIdx` < 100.

| ID / range | Uso |
|---|---|
| 1100000–1100099 | AWSManagedRulesAmazonIpReputationList (`iprep`) |
| 1450000–1450099 | AWSManagedRulesAnonymousIpList (`anonip`, opzionale) |
| 1200000–1200099 | AWSManagedRulesCommonRuleSet (`crs`) |
| 1300000–1300099 | AWSManagedRulesKnownBadInputsRuleSet (`kbi`) |
| 1400000–1400099 | AWSManagedRulesSQLiRuleSet (`sqli`, opzionale) |
| 1410000–1410099 | AWSManagedRulesAdminProtectionRuleSet (`admin`, opzionale) |
| 1420000–1420099 | AWSManagedRulesLinuxRuleSet (`linux`, opzionale) |
| 1430000–1430099 | AWSManagedRulesUnixRuleSet (`unix`, opzionale) |
| 1440000–1440099 | AWSManagedRulesWindowsRuleSet (`windows`, opzionale) |
| 1460000–1460099 | AWSManagedRulesPHPRuleSet (`php`, opzionale) |
| 1470000–1470099 | AWSManagedRulesWordPressRuleSet (`wordpress`, opzionale) |
| per regola B | B+0..6 detector, B+7 label, B+8 terminazione, B+9 azione default AWS |
| 1G00001 | salto del gruppo G (`SecMarker END_GRP_<key>`) |
| 1500000 + siteIdx·1000 + ruleIdx·10 | custom rule del sito |
| 1600000 + siteIdx·1000 + groupIdx·10 (+0, +1) | scope-down per gruppo (fino a 100 gruppi) |
| 1700000 + siteIdx·100 + i | path override (nginx-only) |
| 1900001–1900099 | motore (init, `TX:raw_path`, …) |
| 1910000 + siteIdx·10 + k | variabili del sito |
| 1900800–1900930 | evaluator: 1900800/801 fail, 1900890–892 audit relevant, 1900900 SUMMARY, 1900910–913 FAIL, 1900920 BLOCK, 1900930 DEFAULT_BLOCK |

Mappa id → gruppo/regola/label per ogni rev: `runtime/<rev>/rules-index.json`.

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

### Detector effettivi (generato)

Tabella generata con `wafctl catalog list --group crs --format markdown` dal catalogo
`waf/catalog/rules.yaml` (fonte di verità; la tabella sopra resta come motivazione).
Il path `_URIPATH` è `TX:raw_path` (path grezzo da `REQUEST_URI_RAW`, D7).

| ID | Group | Rule | Default | Fidelity | Detectors(vars → op) |
|---|---|---|---|---|---|
| 1200010 | crs | NoUserAgent_HEADER | block | exact | `&REQUEST_HEADERS:User-Agent → @eq 0` |
| 1200020 | crs | UserAgent_BadBots_HEADER | block | approx | `REQUEST_HEADERS:User-Agent → @pmFromFile /etc/waf/data/bad-bots.data [t:lowercase]` |
| 1200030 | crs | SizeRestrictions_QUERYSTRING | block | exact | `QUERY_STRING → @gt 2048 [t:length]` |
| 1200040 | crs | SizeRestrictions_Cookie_HEADER | block | exact | `REQUEST_HEADERS:Cookie → @gt 10240 [t:length]` |
| 1200050 | crs | SizeRestrictions_BODY | block | approx | `REQUEST_HEADERS:Content-Length → @gt 8192` OR `&REQUEST_HEADERS:Content-Length → @eq 0 AND REQUEST_BODY_LENGTH → @ge 8192` |
| 1200060 | crs | SizeRestrictions_URIPATH | block | exact | `TX:raw_path → @gt 1024 [t:length]` |
| 1200070 | crs | EC2MetaDataSSRF_BODY | block | approx | `REQUEST_BODY → @pmFromFile /etc/waf/data/ec2-metadata.data [t:urlDecodeUni,lowercase]` |
| 1200080 | crs | EC2MetaDataSSRF_COOKIE | block | approx | `REQUEST_COOKIES → @pmFromFile /etc/waf/data/ec2-metadata.data [t:urlDecodeUni,lowercase]` |
| 1200090 | crs | EC2MetaDataSSRF_URIPATH | block | approx | `TX:raw_path → @pmFromFile /etc/waf/data/ec2-metadata.data [t:urlDecodeUni,lowercase]` |
| 1200100 | crs | EC2MetaDataSSRF_QUERYARGUMENTS | block | approx | `ARGS_GET → @pmFromFile /etc/waf/data/ec2-metadata.data [t:urlDecodeUni,lowercase]` |
| 1200110 | crs | GenericLFI_QUERYARGUMENTS | block | approx | `ARGS_GET → @rx (?:^\|[\\/;])\.{2,3}[\\/;] [t:utf8toUnicode,urlDecodeUni,removeNulls]` OR `ARGS_GET → @pmFromFile /etc/waf/data/lfi-targets.data [t:utf8toUnicode,urlDecodeUni,normalizePathWin,lowercase]` |
| 1200120 | crs | GenericLFI_URIPATH | block | approx | `TX:raw_path → @rx (?:^\|[\\/;])\.{2,3}[\\/;] [t:utf8toUnicode,urlDecodeUni,removeNulls]` OR `TX:raw_path → @pmFromFile /etc/waf/data/lfi-targets.data [t:utf8toUnicode,urlDecodeUni,normalizePathWin,lowercase]` |
| 1200130 | crs | GenericLFI_BODY | block | approx | `REQUEST_BODY → @rx (?:^\|[\\/;=:"'\s])\.{2,3}[\\/;] [t:utf8toUnicode,urlDecodeUni,removeNulls]` OR `REQUEST_BODY → @pmFromFile /etc/waf/data/lfi-targets.data [t:utf8toUnicode,urlDecodeUni,normalizePathWin,lowercase]` |
| 1200140 | crs | RestrictedExtensions_URIPATH | block | approx | `TX:raw_path → @rx \.(?:asa\|asax\|backup\|bak\|bat\|cdx\|cer\|cfg\|cmd\|com\|config\|conf\|crt\|cs\|csproj\|csr\|dat\|db\|dbf\|dll\|dos\|htr\|htw\|ida\|idc\|idq\|inc\|ini\|key\|licx\|lnk\|log\|mdb\|old\|pass\|pdb\|pol\|printer\|pwd\|rdb\|resources\|resx\|sql\|swp\|sys\|vb\|vbs\|vbproj\|vsdisco\|webinfo\|xsd\|xsx)$ [t:urlDecodeUni,lowercase]` |
| 1200150 | crs | RestrictedExtensions_QUERYARGUMENTS | block | approx | `ARGS_GET → @rx \.(?:asa\|asax\|backup\|bak\|bat\|cdx\|cer\|cfg\|cmd\|com\|config\|conf\|crt\|cs\|csproj\|csr\|dat\|db\|dbf\|dll\|dos\|htr\|htw\|ida\|idc\|idq\|inc\|ini\|key\|licx\|lnk\|log\|mdb\|old\|pass\|pdb\|pol\|printer\|pwd\|rdb\|resources\|resx\|sql\|swp\|sys\|vb\|vbs\|vbproj\|vsdisco\|webinfo\|xsd\|xsx)$ [t:urlDecodeUni,lowercase]` |
| 1200160 | crs | GenericRFI_QUERYARGUMENTS | block | approx | `ARGS_GET → @rx (?:file\|ftps?\|https?)://(?:[0-9]{1,3}\.){3}[0-9]{1,3} [t:urlDecodeUni,lowercase]` |
| 1200170 | crs | GenericRFI_BODY | block | approx | `REQUEST_BODY → @rx (?:file\|ftps?\|https?)://(?:[0-9]{1,3}\.){3}[0-9]{1,3} [t:urlDecodeUni,lowercase]` |
| 1200180 | crs | GenericRFI_URIPATH | block | approx | `TX:raw_path → @rx (?:file\|ftps?\|https?):/{1,2}(?:[0-9]{1,3}\.){3}[0-9]{1,3} [t:urlDecodeUni,lowercase]` |
| 1200190 | crs | CrossSiteScripting_COOKIE | block | approx | `REQUEST_COOKIES → @detectXSS [t:utf8toUnicode,urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls]` OR `REQUEST_COOKIES → @rx (?i)<script[^>]*> [t:utf8toUnicode,urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls]` |
| 1200200 | crs | CrossSiteScripting_QUERYARGUMENTS | block | approx | `ARGS_GET → @detectXSS [t:utf8toUnicode,urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls]` OR `ARGS_GET → @rx (?i)<script[^>]*> [t:utf8toUnicode,urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls]` |
| 1200210 | crs | CrossSiteScripting_BODY | block | approx | `REQUEST_BODY → @detectXSS [t:utf8toUnicode,urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls]` OR `REQUEST_BODY → @rx (?i)<script[^>]*> [t:utf8toUnicode,urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls]` |
| 1200220 | crs | CrossSiteScripting_URIPATH | block | approx | `TX:raw_path → @detectXSS [t:utf8toUnicode,urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls]` OR `TX:raw_path → @rx (?i)<script[^>]*> [t:utf8toUnicode,urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls]` |

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

## 5b. Gruppi opzionali per caso d'uso (AWS "use-case" e "OS" rule group)

Tutti opzionali (`enabled: true` nel sito o nel profilo). I pattern AWS non sono pubblici: i detector
sono ricostruzioni (fidelity `approx`) dai nomi e dalle descrizioni della documentazione
(`docs/aws/managed-rules-use-case.md`), tarate per non bloccare il traffico normale. Trasformazioni:
`utf8toUnicode, urlDecodeUni, removeNulls, lowercase` (+ `normalizePath` sui path).

| Gruppo (WCU) | Label prefix | Regole (ID) | Rileva |
|---|---|---|---|
| AdminProtection (100) | `admin-protection:` | AdminProtection_URIPATH (1410010) | pagine di amministrazione note: `/admin`, `/wp-admin`, phpMyAdmin, Adminer, Tomcat manager, JBoss/JMX, actuator, `server-status` |
| Linux (200) | `linux-os:` | LFI_URIPATH, LFI_QUERYSTRING, LFI_HEADER (1420010–30) | percorsi di file di sistema Linux (`waf/data/linux-lfi.data`: `/etc/passwd`, `/proc/self/`, `.ssh/id_`, `.aws/credentials`…) |
| Unix/POSIX (100) | `posix-os:` | UNIXShellCommandsVariables_QUERYSTRING, _BODY, _HEADER (1430010–30) | command injection: `;id`, `\|whoami`, `$(curl …)`, `` `id` ``, `wget/curl http://`, `nc host port`, `sh -c '…'`, `/bin/sh`, `${IFS}` |
| Windows (200) | `windows-os:` | WindowsShellCommands_HEADER, _QUERYARGUMENTS, _QUERYSTRING, _URIPATH, _BODY; PowerShellCommands_COOKIE, _QUERYARGUMENTS, _BODY (1440010–80) | `cmd /c`, `net user`, `certutil -urlcache`, `c:\windows\system32\`, `%COMSPEC%`; PowerShell `Invoke-Expression`, `IEX(`, `DownloadString(`, `-enc <base64>` |
| PHP (100) | `php-app:` | PHPHighRiskMethodsVariables_HEADER, _QUERYSTRING, _BODY, _URIPATH; PHP2Shell_BODY, PHP2Shell_BODY_Extended; **Count**: PHPUploadProgressSerializedObject_BODY, PHPFPMSmuggling_BODY (1460010–80) | `$_GET`/`$_POST`…, `system(`/`eval(`/`base64_decode(` con argomento, wrapper `php://` `phar://` `data:`, `<?php`, ThinkPHP `invokefunction`; PHP-CGI `-d allow_url_include=`; oggetti serializzati in `PHP_SESSION_UPLOAD_PROGRESS`. PHPFPMSmuggling_BODY è uno stub |
| WordPress (100) | `wordpress-app:` | WordPressExploitableCommands_QUERYSTRING, WordPressExploitablePaths_URIPATH (1470010–20) | `xmlrpc.php`, `wp-config.php*`, `wp-admin/install.php`, `setup-config.php`, PHP in `wp-content/uploads`, `debug.log`, `wlwmanifest.xml`, comandi di plugin vulnerabili (`do-reset-wordpress`, `revslider_show_image`, wp-file-manager) |

Ordine di valutazione (priorità): iprep → anonip → crs → kbi → sqli → admin → linux → unix → windows → php → wordpress.
WCU: AWS consente fino a 1500 WCU per web ACL senza costi aggiuntivi (max 5000): il profilo `wordpress`
(~1650 WCU con le custom rule) supera la soglia gratuita se esportato su AWS.

## 6. Avvertenze per i test

- **Host_localhost_HEADER blocca `curl http://localhost:8080`**: è il comportamento AWS reale. Nei test usare un host
  come `app.localtest.me` o `-H 'Host: example.com'`.
- **NoUserAgent_HEADER**: `curl` invia sempre UA; per provarlo usare `-A ''` / `-H 'User-Agent:'`.
- IP reputation: dietro Docker `REMOTE_ADDR` è il gateway della bridge → usare la modalità test XFF con `203.0.113.x`.

## 7. Punti aperti

1. Verificare priority e versione dei rule group nella web ACL one-click reale (`aws wafv2 get-web-acl`, serve MFA).
2. Scaricare `describe-managed-rule-group` per confermare nomi regole e versione statica corrente.
3. ~~Formato log~~ **Risolto (D16):** access log JSON nginx + audit log JSON ModSecurity, uniti da Vector per `request_id` in eventi con `terminating_rule`, `labels`, `action`, `aws_default_action` (+ `matches.jsonl` per regola).
4. ~~Variabile path~~ **Risolto (D7):** i detector `_URIPATH` usano `TX:raw_path` (path grezzo); le regole a pattern aggiungono `t:urlDecodeUni`, quelle di dimensione usano la lunghezza grezza.
