-- Configurazione attiva di ogni sito, pubblicata dal WAF a ogni reload (bin/waf-publish).
-- Equivalente della pagina "Rules" di una Web ACL AWS: gruppi con WCU, regole con azione di default
-- ed effettiva, regole custom, impostazioni. Per la config attuale: l'ultima config_rev di ogni sito.
-- Su un'installazione esistente:
--   docker compose exec -T clickhouse clickhouse-client -u waf_admin --password <pwd> --multiquery < clickhouse/initdb/004-site-rules.sql
CREATE TABLE IF NOT EXISTS waf.site_rules
(
    ts DateTime64(3, 'UTC'),
    node_id LowCardinality(String),
    site_id LowCardinality(String),
    config_rev LowCardinality(String),
    position UInt16,
    kind LowCardinality(String),            -- group | managed | custom | setting | path_override | scope_down
    rule_group LowCardinality(String),
    rule_name LowCardinality(String),
    default_action LowCardinality(String),
    effective_action LowCardinality(String),
    origin LowCardinality(String),          -- default | profile:... | site | ...
    fidelity LowCardinality(String),        -- approx | stub | exact (fedeltà rispetto ad AWS)
    wcu UInt32,                             -- group: WCU del gruppo gestito; custom: stima
    detail String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (site_id, ts, position)
TTL toDateTime(ts) + INTERVAL 400 DAY;

-- Ultima configurazione di ogni sito
CREATE VIEW IF NOT EXISTS waf.site_rules_current AS
SELECT r.*
FROM waf.site_rules AS r
INNER JOIN (SELECT site_id, max(ts) AS last_ts FROM waf.site_rules GROUP BY site_id) AS l
    ON r.site_id = l.site_id AND r.ts = l.last_ts;
