"""Panel table of the WAF dashboards (input of scripts/gen-dashboards.py; never edit the JSON).

Each panel: {title, type: timeseries|table|stat|barchart|piechart, ds: ch|prom, sql|expr, w, h,
unit?, stack?, legend?, x? (barchart x field)}. Panels are laid out row-major on a 24-column grid.
"""

SITE = "('__all__' IN (${site:singlequote}) OR site_id IN (${site:singlequote}))"
AGG = "FROM waf.agg_requests_1m WHERE $__timeFilter(minute) AND " + SITE
MAGG = "FROM waf.agg_matches_1m WHERE $__timeFilter(minute) AND " + SITE
EV = "FROM waf.events WHERE $__timeFilter(ts) AND " + SITE

SITE_VAR = {
    "name": "site", "label": "Sito", "type": "query", "ds": "ch", "multi": True, "includeAll": True, "allValue": "'__all__'",
    "query": "SELECT DISTINCT site_id FROM waf.agg_requests_1m WHERE minute > now() - INTERVAL 30 DAY ORDER BY site_id",
}

DASHBOARDS = [
    {
        "uid": "waf-overview", "title": "WAF Overview", "vars": [SITE_VAR],
        "panels": [
            {"title": "Richieste", "type": "stat", "ds": "ch", "w": 4, "h": 4, "unit": "short",
             "sql": "SELECT sum(requests) AS requests " + AGG},
            {"title": "Bloccate", "type": "stat", "ds": "ch", "w": 4, "h": 4, "unit": "short",
             "sql": "SELECT sumIf(requests, action = 'BLOCK') AS blocked " + AGG},
            {"title": "Block %", "type": "stat", "ds": "ch", "w": 4, "h": 4, "unit": "percent",
             "sql": "SELECT round(100 * sumIf(requests, action = 'BLOCK') / greatest(sum(requests), 1), 2) AS block_pct " + AGG},
            {"title": "FAIL", "type": "stat", "ds": "ch", "w": 4, "h": 4, "unit": "short",
             "sql": "SELECT sumIf(requests, action = 'FAIL') AS fail " + AGG},
            {"title": "Block AWS default", "type": "stat", "ds": "ch", "w": 4, "h": 4, "unit": "short",
             "sql": "SELECT sumIf(requests, aws_default_action = 'BLOCK') AS aws_default_block " + AGG},
            {"title": "Disaccordi vs AWS default", "type": "stat", "ds": "ch", "w": 4, "h": 4, "unit": "short",
             "sql": "SELECT sumIf(requests, action != aws_default_action) AS disagreements " + AGG},
            {"title": "Richieste per azione", "type": "timeseries", "ds": "ch", "w": 8, "h": 8, "unit": "short", "stack": True,
             "sql": "SELECT $__timeInterval(minute) AS time, action, sum(requests) AS requests " + AGG + " GROUP BY time, action ORDER BY time"},
            {"title": "Blocchi per sito", "type": "timeseries", "ds": "ch", "w": 8, "h": 8, "unit": "short",
             "sql": "SELECT $__timeInterval(minute) AS time, site_id, sumIf(requests, action = 'BLOCK') AS blocked " + AGG + " GROUP BY time, site_id ORDER BY time"},
            {"title": "Classi di status", "type": "timeseries", "ds": "ch", "w": 8, "h": 8, "unit": "short", "stack": True,
             "sql": "SELECT $__timeInterval(minute) AS time, concat(toString(status_class), 'xx') AS status, sum(requests) AS requests " + AGG + " GROUP BY time, status ORDER BY time"},
            {"title": "Regole terminanti (top)", "type": "table", "ds": "ch", "w": 12, "h": 10,
             "sql": "SELECT rule_group, rule_name, sum(matches) AS matches " + MAGG + " AND post_terminating = 0 AND configured_action != 'COUNT' GROUP BY rule_group, rule_name ORDER BY matches DESC LIMIT 20"},
            {"title": "Siti per blocchi", "type": "table", "ds": "ch", "w": 12, "h": 10,
             "sql": "SELECT site_id, sum(requests) AS total, sumIf(requests, action = 'BLOCK') AS blocked, round(100 * blocked / greatest(total, 1), 2) AS block_pct " + AGG + " GROUP BY site_id ORDER BY blocked DESC LIMIT 50"},
        ],
    },
    {
        "uid": "waf-tuning", "title": "WAF Rules & Tuning", "vars": [SITE_VAR],
        "panels": [
            {"title": "Regole in COUNT per sito (candidati would-block)", "type": "table", "ds": "ch", "w": 24, "h": 10,
             "sql": "SELECT site_id, rule_group, rule_name, sum(matches) AS matches " + MAGG + " AND configured_action = 'COUNT' GROUP BY site_id, rule_group, rule_name ORDER BY matches DESC LIMIT 100"},
            {"title": "Match per regola (top 10)", "type": "timeseries", "ds": "ch", "w": 24, "h": 9, "unit": "short",
             "sql": "SELECT $__timeInterval(minute) AS time, rule_name, sum(matches) AS matches " + MAGG
                    + " AND rule_name IN (SELECT rule_name " + MAGG + " GROUP BY rule_name ORDER BY sum(matches) DESC LIMIT 10) GROUP BY time, rule_name ORDER BY time"},
            {"title": "Disaccordi vs AWS default per sito e user_class", "type": "table", "ds": "ch", "w": 12, "h": 10,
             "sql": "SELECT site_id, user_class, action, aws_default_action, sum(requests) AS requests " + AGG + " AND action != aws_default_action GROUP BY site_id, user_class, action, aws_default_action ORDER BY requests DESC LIMIT 100"},
            {"title": "Path delle regole in COUNT", "type": "table", "ds": "ch", "w": 12, "h": 10,
             "sql": "SELECT rule_name, path, count() AS matches FROM waf.matches WHERE $__timeFilter(ts) AND " + SITE + " AND configured_action = 'COUNT' GROUP BY rule_name, path ORDER BY matches DESC LIMIT 100"},
            {"title": "Match per user_class", "type": "barchart", "ds": "ch", "w": 24, "h": 8, "x": "user_class",
             "sql": "SELECT user_class, sum(matches) AS matches " + MAGG + " GROUP BY user_class ORDER BY matches DESC"},
        ],
    },
    {
        "uid": "waf-explorer", "title": "WAF Request Explorer",
        "vars": [
            SITE_VAR,
            {"name": "ip", "label": "IP", "type": "textbox"},
            {"name": "rule", "label": "Regola terminante", "type": "textbox"},
            {"name": "action", "label": "Azione", "type": "custom", "multi": True, "includeAll": True, "allValue": "'__all__'", "query": "ALLOW,BLOCK,FAIL"},
            {"name": "rid", "label": "Request ID", "type": "textbox"},
        ],
        "panels": [
            {"title": "Ultimi 500 eventi", "type": "table", "ds": "ch", "w": 24, "h": 12,
             "sql": "SELECT ts, site_id, client_ip, country, method, path, status, action, shadow_action, terminating_rule, request_id " + EV
                    + " AND (${ip:sqlstring} = '' OR client_ip = ${ip:sqlstring})"
                    + " AND (${rule:sqlstring} = '' OR terminating_rule = ${rule:sqlstring} OR endsWith(terminating_rule, concat('/', ${rule:sqlstring})))"
                    + " AND ('__all__' IN (${action:singlequote}) OR action IN (${action:singlequote}))"
                    + " ORDER BY ts DESC LIMIT 500"},
            {"title": "Match della richiesta $rid", "type": "table", "ds": "ch", "w": 24, "h": 8,
             "sql": "SELECT rule_group, rule_name, configured_action, in_scope, post_terminating, variable, value FROM waf.matches WHERE $__timeFilter(ts) AND request_id = ${rid:sqlstring} ORDER BY post_terminating, rule_id"},
            {"title": "Paesi", "type": "piechart", "ds": "ch", "w": 12, "h": 9,
             "sql": "SELECT if(country = '', '??', country) AS cc, count() AS requests " + EV + " GROUP BY cc ORDER BY requests DESC LIMIT 15"},
            {"title": "ASN (top)", "type": "table", "ds": "ch", "w": 12, "h": 9,
             "sql": "SELECT asn, as_org, count() AS requests, countIf(action = 'BLOCK') AS blocked " + EV + " GROUP BY asn, as_org ORDER BY requests DESC LIMIT 20"},
        ],
    },
    {
        "uid": "waf-nodes", "title": "WAF Nodes Health", "vars": [],
        "panels": [
            {"title": "Heartbeat dei nodi", "type": "table", "ds": "ch", "w": 24, "h": 8,
             "sql": "SELECT node_id, argMax(version, ts) AS version, argMax(config_rev, ts) AS config_rev, max(ts) AS last_seen, dateDiff('second', max(ts), now64(3)) AS age_s FROM waf.heartbeats GROUP BY node_id ORDER BY node_id"},
            {"title": "Richieste/s nginx", "type": "timeseries", "ds": "prom", "w": 12, "h": 8, "unit": "reqps",
             "expr": "sum by (node_id) (rate(nginx_http_requests_total[1m]))", "legend": "{{node_id}}"},
            {"title": "Connessioni attive nginx", "type": "timeseries", "ds": "prom", "w": 12, "h": 8, "unit": "short",
             "expr": "sum by (node_id) (nginx_connections_active)", "legend": "{{node_id}}"},
            {"title": "CPU occupata", "type": "timeseries", "ds": "prom", "w": 12, "h": 8, "unit": "percent",
             "expr": "100 * (1 - avg by (node_id) (rate(host_cpu_seconds_total{mode=\"idle\"}[1m])))", "legend": "{{node_id}}"},
            {"title": "Memoria disponibile", "type": "timeseries", "ds": "prom", "w": 12, "h": 8, "unit": "bytes",
             "expr": "host_memory_available_bytes", "legend": "{{node_id}}"},
            {"title": "Buffer Vector", "type": "timeseries", "ds": "prom", "w": 8, "h": 8, "unit": "bytes",
             "expr": "sum by (node_id) (vector_buffer_size_bytes)", "legend": "{{node_id}}"},
            {"title": "Errori componenti Vector", "type": "timeseries", "ds": "prom", "w": 8, "h": 8, "unit": "short",
             "expr": "sum by (node_id, component_id) (rate(vector_component_errors_total[5m]))", "legend": "{{node_id}} {{component_id}}"},
            {"title": "Query ClickHouse in corso", "type": "timeseries", "ds": "prom", "w": 8, "h": 8, "unit": "short",
             "expr": "ClickHouseMetrics_Query{job=\"clickhouse\"}", "legend": "clickhouse"},
        ],
    },
]
