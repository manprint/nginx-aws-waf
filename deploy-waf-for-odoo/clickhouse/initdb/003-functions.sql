-- Funzioni per leggere i log in italiano (usate dalla dashboard "WAF Richieste").
-- Eseguito al primo avvio (data/clickhouse vuota). Su un'installazione esistente:
--   docker compose exec -T clickhouse clickhouse-client -u waf_admin --password <pwd> --multiquery < clickhouse/initdb/003-functions.sql

-- Tipo di attacco/controllo a partire dal nome della regola (AWS managed, custom Odoo, rate limit).
CREATE OR REPLACE FUNCTION waf_causa AS (rule_name, terminating_type) -> multiIf(
    terminating_type = 'RATE_BASED',                     'Troppe richieste dallo stesso IP (rate limit)',
    rule_name = 'AWSManagedIPReputationList',            'IP con cattiva reputazione (liste Amazon/Spamhaus)',
    rule_name = 'AWSManagedReconnaissanceList',          'IP noto per scansioni e ricognizione',
    rule_name = 'AWSManagedIPDDoSList',                  'IP coinvolto in attacchi DDoS',
    rule_name = 'AnonymousIPList',                       'IP anonimo (Tor, VPN, proxy)',
    rule_name = 'HostingProviderIPList',                 'IP di un provider cloud/hosting (probabile bot)',
    rule_name = 'GeoBlock',                              'Paese bloccato (geo_block)',
    rule_name = 'OdooBlockDatabaseManager',              'Gestione database Odoo (/web/database/*) non consentita',
    rule_name = 'OdooBlockXmlrpcDb',                     'Servizio XML-RPC db di Odoo (crea/copia/cancella database) non consentito',
    rule_name = 'BlockSensitiveFiles',                   'File riservato (.env, .git, chiavi, backup, composer.json, ...)',
    rule_name = 'BlockScannerProbes',                    'Percorso cercato dagli scanner di exploit (phpunit, actuator, cgi-bin, ...)',
    rule_name = 'BlockDebugMethods',                     'Metodo HTTP di debug (TRACE, TRACK, DEBUG, CONNECT)',
    rule_name = 'BlockPhpProbes',                        'Webshell o pagina di diagnostica PHP (phpinfo.php, shell.php, ...)',
    rule_name = 'BlockDbAdminTools',                     'Strumento di amministrazione database (phpMyAdmin, Adminer)',
    rule_name = 'BlockServerSideScripts',                'Script lato server su un sito statico (.php, .asp, .jsp, ...)',
    rule_name = 'BlockWriteMethods',                     'Metodo di scrittura (POST/PUT/DELETE) su un sito statico',
    rule_name LIKE 'WordPressBlockUserEnum%',            'Enumerazione degli utenti WordPress (?author=, /wp/v2/users)',
    rule_name = 'WordPressBlockFingerprintFiles',        'File che rivelano la versione di WordPress/plugin (readme, license)',
    rule_name = 'WordPressExploitablePaths_URIPATH',     'Percorso WordPress sfruttabile (xmlrpc.php, wp-config.php, PHP negli upload)',
    rule_name = 'WordPressExploitableCommands_QUERYSTRING', 'Comando di un plugin WordPress vulnerabile',
    rule_name = 'AdminProtection_URIPATH',               'Pagina di amministrazione esposta (admin, phpMyAdmin, manager)',
    rule_name LIKE 'LFI_%',                               'Lettura di file di sistema Linux (/etc/passwd, /proc/self, ...)',
    rule_name LIKE 'UNIXShellCommands%' OR rule_name = 'WordPressShellBodyOutsideEditor', 'Command injection Unix (;id, $(curl ...), /bin/sh)',
    rule_name LIKE 'WindowsShellCommands%',              'Command injection Windows (cmd.exe, net user, certutil)',
    rule_name LIKE 'PowerShellCommands%',                'Comandi PowerShell (Invoke-Expression, DownloadString)',
    rule_name LIKE 'PHPHighRisk%' OR rule_name = 'WordPressPhpBodyOutsideEditor', 'Iniezione di codice PHP (system(), $_GET, php://, <?php)',
    rule_name LIKE 'PHP2Shell%',                         'PHP-CGI: modifica della configurazione PHP (-d allow_url_include)',
    rule_name LIKE 'PHPUploadProgress%',                 'Oggetto PHP serializzato nell''upload progress',
    rule_name LIKE 'NoUserAgent%',                       'Header User-Agent mancante',
    rule_name LIKE 'UserAgent_BadBots%',                 'User-Agent di bot o scanner malevolo',
    rule_name ILIKE '%SizeRestrictions%' OR rule_name ILIKE '%BodySize%', 'Richiesta troppo grande (limite di dimensione)',
    rule_name LIKE 'EC2MetaDataSSRF%',                   'SSRF verso i metadati cloud (169.254.169.254)',
    rule_name LIKE 'GenericLFI%' OR rule_name = 'WordPressLfiBodyOutsideEditor', 'Path traversal / Local File Inclusion (../)',
    rule_name LIKE 'RestrictedExtensions%',              'Estensione di file vietata (.log, .ini, .bak, ...)',
    rule_name ILIKE '%RFI%',                             'Remote File Inclusion (URL esterno come parametro)',
    rule_name LIKE 'CrossSiteScripting%' OR rule_name ILIKE '%Xss%', 'Cross-Site Scripting (XSS)',
    rule_name LIKE 'JavaDeserializationRCE%',            'Deserializzazione Java (esecuzione di codice)',
    rule_name = 'Host_localhost_HEADER',                 'Header Host = localhost',
    rule_name = 'PROPFIND_METHOD',                       'Metodo WebDAV PROPFIND',
    rule_name = 'ExploitablePaths_URIPATH',              'Percorso sensibile (es. /.git, /WEB-INF, /admin di framework)',
    rule_name LIKE 'Log4JRCE%',                          'Log4Shell (${jndi:...}, Log4j RCE)',
    rule_name LIKE 'ReactJSRCE%',                        'Esecuzione di codice in React Server Components',
    rule_name = 'ApacheMod_HTTP2',                       'Exploit Apache mod_http2',
    rule_name LIKE 'Java4Shell%',                        'Spring4Shell (Java RCE)',
    rule_name LIKE 'Ruby2Shell%',                        'Esecuzione di codice Ruby (method override)',
    rule_name ILIKE '%SQLi%',                            'SQL injection',
    rule_name = '' OR rule_name = 'Default_Action',      '',
    concat('Regola personalizzata: ', rule_name));

-- Dove è stato trovato il contenuto sospetto (variabile ModSecurity → italiano).
CREATE OR REPLACE FUNCTION waf_dove AS (variable) -> multiIf(
    variable = '',                                '',
    startsWith(variable, 'ARGS_GET:'),            concat('parametro URL «', substring(variable, 10), '»'),
    startsWith(variable, 'ARGS_POST:'),           concat('campo del form «', substring(variable, 11), '»'),
    startsWith(variable, 'ARGS:'),                concat('parametro «', substring(variable, 6), '»'),
    startsWith(variable, 'ARGS_NAMES'),           'nome di un parametro',
    startsWith(variable, 'REQUEST_HEADERS:'),     concat('header «', substring(variable, 17), '»'),
    startsWith(variable, 'REQUEST_COOKIES_NAMES'), 'nome di un cookie',
    startsWith(variable, 'REQUEST_COOKIES:'),     concat('cookie «', substring(variable, 17), '»'),
    startsWith(variable, 'REQUEST_BODY') OR startsWith(variable, 'XML') OR startsWith(variable, 'JSON'), 'body della richiesta',
    startsWith(variable, 'FILES'),                'file caricato',
    variable IN ('REQUEST_URI', 'REQUEST_URI_RAW', 'REQUEST_FILENAME', 'REQUEST_BASENAME') OR variable ILIKE 'TX:%path%' OR variable ILIKE 'TX:%uri%', 'percorso URL',
    variable IN ('QUERY_STRING', 'ARGS_GET_NAMES'), 'query string',
    variable = 'REMOTE_ADDR',                     'IP del client',
    variable = 'REQUEST_METHOD',                  'metodo HTTP',
    variable = 'REQUEST_LINE',                    'riga della richiesta',
    variable);

-- Frase completa: "Cross-Site Scripting (XSS) — parametro URL «q»: <script>alert(1)</script>"
CREATE OR REPLACE FUNCTION waf_spiega AS (rule_name, terminating_type, variable, value) -> concat(
    waf_causa(rule_name, terminating_type),
    if(variable = '', '', concat(' — ', waf_dove(variable))),
    if(value = '' OR value = '0', '', concat(': ', substring(replaceRegexpAll(value, '\\s+', ' '), 1, 160))));
