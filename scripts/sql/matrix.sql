-- Lab matrix over one day of raw logs (clickhouse local). Param: d = YYYY-MM-DD.
-- Schemas: column lists of waf.events / waf.matches in snippets/clickhouse-ddl.sql (no codecs/defaults).
SET date_time_input_format = 'best_effort', input_format_skip_unknown_fields = 1;
-- waf_test: X-Waf-Test value, header name matched case-insensitively (raw logs keep the client's case).
CREATE TEMPORARY TABLE ev AS SELECT *, arrayStringConcat(mapValues(mapFilter((k, v) -> lower(k) = 'x-waf-test', request_headers))) AS waf_test FROM file(concat('/raw/', {d:String}, '/events.jsonl'), 'JSONEachRow', 'ts DateTime64(3, \'UTC\'), request_id String, node_id LowCardinality(String), site_id LowCardinality(String), app LowCardinality(String), host String, client_ip String, client_port UInt16, peer_ip String, country LowCardinality(String), asn UInt32, as_org LowCardinality(String), method LowCardinality(String), scheme LowCardinality(String), http_version LowCardinality(String), tls_protocol LowCardinality(String), uri String, path String, query String, status UInt16, bytes_sent UInt64, request_length UInt64, request_time Float32, upstream_time Float32, upstream_status String, upstream_addr String, user_agent String, referer String, content_type String, content_length Int64, user_class LowCardinality(String), rate_limit_status LowCardinality(String), waf_inspected UInt8, waf_mode LowCardinality(String), action LowCardinality(String), shadow_action LowCardinality(String), terminating_rule_id UInt32, terminating_rule LowCardinality(String), terminating_type LowCardinality(String), aws_default_action LowCardinality(String), aws_default_rule LowCardinality(String), labels Array(LowCardinality(String)), match_count UInt16, fail_reason LowCardinality(String), request_headers Map(String, String), response_headers Map(String, String), request_body String');
CREATE TEMPORARY TABLE ma AS SELECT * FROM file(concat('/raw/', {d:String}, '/matches.jsonl'), 'JSONEachRow', 'ts DateTime64(3, \'UTC\'), request_id String, node_id LowCardinality(String), site_id LowCardinality(String), rule_id UInt32, rule_group LowCardinality(String), rule_name LowCardinality(String), label LowCardinality(String), configured_action LowCardinality(String), in_scope UInt8, post_terminating UInt8, aws_post_terminating UInt8, variable String, value String, method LowCardinality(String), path String, client_ip String, user_class LowCardinality(String), request_action LowCardinality(String)');

SELECT '## 1. Per site: actions, AWS default actions, disagreements' AS ` ` FORMAT TSVRaw;
SELECT site_id, count() AS total,
       countIf(action = 'ALLOW') AS allow, countIf(action = 'BLOCK') AS block, countIf(action = 'COUNT') AS count_,
       countIf(aws_default_action = 'ALLOW') AS aws_allow, countIf(aws_default_action = 'BLOCK') AS aws_block,
       countIf(action != aws_default_action AND aws_default_action != '') AS disagree,
       countIf(action != aws_default_action AND aws_default_action != '' AND user_class = 'backend') AS dis_backend,
       countIf(action != aws_default_action AND aws_default_action != '' AND user_class = 'website') AS dis_website,
       countIf(action != aws_default_action AND aws_default_action != '' AND user_class = 'static') AS dis_static,
       countIf(action != aws_default_action AND aws_default_action != '' AND user_class = 'realtime') AS dis_realtime,
       countIf(action != aws_default_action AND aws_default_action != '' AND user_class NOT IN ('backend', 'website', 'static', 'realtime')) AS dis_other
FROM ev GROUP BY site_id ORDER BY site_id FORMAT Markdown;

SELECT '\n## 2. Per rule: matches per site and configured action' AS ` ` FORMAT TSVRaw;
SELECT rule_group, rule_name, site_id, configured_action, count() AS matches
FROM ma WHERE post_terminating = 0
GROUP BY rule_group, rule_name, site_id, configured_action
ORDER BY rule_group, rule_name, site_id, configured_action FORMAT Markdown;

SELECT '\n## 3. Top 20 disagreements (action != aws_default_action)' AS ` ` FORMAT TSVRaw;
SELECT site_id, path, action, terminating_rule, aws_default_action, aws_default_rule, count() AS n
FROM ev WHERE aws_default_action != '' AND action != aws_default_action
GROUP BY site_id, path, action, terminating_rule, aws_default_action, aws_default_rule
ORDER BY n DESC, site_id, path LIMIT 20 FORMAT Markdown;

SELECT '\n## 4. Legit runs: BLOCK rows (must be 0)' AS ` ` FORMAT TSVRaw;
SELECT count() AS legit_blocks FROM ev
WHERE waf_test LIKE '%-legit' AND action = 'BLOCK' FORMAT Markdown;
SELECT site_id, method, path, terminating_rule, waf_test AS run
FROM ev WHERE waf_test LIKE '%-legit' AND action = 'BLOCK'
ORDER BY ts LIMIT 50 FORMAT Markdown;

SELECT '\n## 5. Attack runs (nuclei, nikto): block rate per site' AS ` ` FORMAT TSVRaw;
SELECT site_id,
       multiIf(waf_test LIKE '%-nuclei', 'nuclei', 'nikto') AS tool,
       count() AS requests, countIf(action = 'BLOCK') AS blocked,
       round(100 * blocked / requests, 1) AS block_pct
FROM ev
WHERE waf_test LIKE '%-nuclei' OR user_agent LIKE '%-nikto%'
GROUP BY site_id, tool ORDER BY site_id, tool FORMAT Markdown;
