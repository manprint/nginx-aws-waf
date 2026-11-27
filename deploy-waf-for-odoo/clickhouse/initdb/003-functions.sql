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
    rule_name LIKE 'NoUserAgent%',                       'Header User-Agent mancante',
    rule_name LIKE 'UserAgent_BadBots%',                 'User-Agent di bot o scanner malevolo',
    rule_name ILIKE '%SizeRestrictions%' OR rule_name ILIKE '%BodySize%', 'Richiesta troppo grande (limite di dimensione)',
    rule_name LIKE 'EC2MetaDataSSRF%',                   'SSRF verso i metadati cloud (169.254.169.254)',
    rule_name LIKE 'GenericLFI%',                        'Path traversal / Local File Inclusion (../)',
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
