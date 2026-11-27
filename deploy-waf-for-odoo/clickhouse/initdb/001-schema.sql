CREATE DATABASE IF NOT EXISTS waf;

CREATE TABLE IF NOT EXISTS waf.events
(
    ts DateTime64(3, 'UTC'),
    request_id String,
    node_id LowCardinality(String),
    site_id LowCardinality(String),
    app LowCardinality(String),
    host String,
    client_ip String,
    client_port UInt16,
    peer_ip String,
    country LowCardinality(String),
    asn UInt32,
    as_org LowCardinality(String),
    method LowCardinality(String),
    scheme LowCardinality(String),
    http_version LowCardinality(String),
    tls_protocol LowCardinality(String),
    uri String,
    path String,
    query String,
    status UInt16,
    bytes_sent UInt64,
    request_length UInt64,
    request_time Float32,
    upstream_time Float32,
    upstream_status String,
    upstream_addr String,
    user_agent String,
    referer String,
    content_type String,
    content_length Int64,
    user_class LowCardinality(String),
    rate_limit_status LowCardinality(String),
    waf_inspected UInt8,
    waf_mode LowCardinality(String),
    action LowCardinality(String),
    shadow_action LowCardinality(String),
    terminating_rule_id UInt32,
    terminating_rule LowCardinality(String),
    terminating_type LowCardinality(String),
    aws_default_action LowCardinality(String),
    aws_default_rule LowCardinality(String),
    labels Array(LowCardinality(String)),
    match_count UInt16,
    fail_reason LowCardinality(String),
    request_headers Map(String, String),
    response_headers Map(String, String),
    request_body String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (site_id, ts, request_id)
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS waf.matches
(
    ts DateTime64(3, 'UTC'),
    request_id String,
    node_id LowCardinality(String),
    site_id LowCardinality(String),
    rule_id UInt32,
    rule_group LowCardinality(String),
    rule_name LowCardinality(String),
    label LowCardinality(String),
    configured_action LowCardinality(String),
    in_scope UInt8,
    post_terminating UInt8,
    aws_post_terminating UInt8,
    variable String,
    value String,
    method LowCardinality(String),
    path String,
    client_ip String,
    user_class LowCardinality(String),
    request_action LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (site_id, rule_name, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS waf.agg_requests_1m
(
    minute DateTime('UTC'),
    node_id LowCardinality(String),
    site_id LowCardinality(String),
    action LowCardinality(String),
    aws_default_action LowCardinality(String),
    user_class LowCardinality(String),
    status_class UInt8,
    requests UInt64,
    bytes_sent UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (site_id, node_id, minute, action, aws_default_action, user_class, status_class)
TTL minute + INTERVAL 400 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS waf.mv_agg_requests_1m TO waf.agg_requests_1m AS
SELECT toStartOfMinute(ts) AS minute, node_id, site_id, action, aws_default_action, user_class,
       toUInt8(intDiv(status, 100)) AS status_class, count() AS requests, sum(bytes_sent) AS bytes_sent
FROM waf.events
GROUP BY minute, node_id, site_id, action, aws_default_action, user_class, status_class;

CREATE TABLE IF NOT EXISTS waf.agg_matches_1m
(
    minute DateTime('UTC'),
    node_id LowCardinality(String),
    site_id LowCardinality(String),
    rule_group LowCardinality(String),
    rule_name LowCardinality(String),
    configured_action LowCardinality(String),
    post_terminating UInt8,
    user_class LowCardinality(String),
    matches UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (site_id, node_id, minute, rule_group, rule_name, configured_action, post_terminating, user_class)
TTL minute + INTERVAL 400 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS waf.mv_agg_matches_1m TO waf.agg_matches_1m AS
SELECT toStartOfMinute(ts) AS minute, node_id, site_id, rule_group, rule_name, configured_action,
       post_terminating, user_class, count() AS matches
FROM waf.matches
GROUP BY minute, node_id, site_id, rule_group, rule_name, configured_action, post_terminating, user_class;

CREATE TABLE IF NOT EXISTS waf.heartbeats
(
    ts DateTime64(3, 'UTC'),
    node_id LowCardinality(String),
    version String,
    config_rev String,
    sites Array(String)
)
ENGINE = ReplacingMergeTree(ts)
ORDER BY node_id
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE;
