#!/bin/bash
set -e
clickhouse client -n <<EOSQL
CREATE USER IF NOT EXISTS waf_ingest IDENTIFIED WITH sha256_password BY '${WAF_CH_INGEST_PASSWORD}';
GRANT INSERT, SELECT ON waf.* TO waf_ingest;
CREATE USER IF NOT EXISTS waf_ro IDENTIFIED WITH sha256_password BY '${WAF_CH_RO_PASSWORD}' SETTINGS readonly = 2;
GRANT SELECT ON waf.* TO waf_ro;
EOSQL
