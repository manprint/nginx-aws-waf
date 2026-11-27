#!/usr/bin/env bash
# Metrics path (4.1): node Vector → vector-central :9598 → Prometheus. Needs the central stack.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
P="${WAF_COMPOSE_PROJECT:-waf}-prometheus-1"
NODE="${WAF_NODE_ID:-lab-node-1}"
pq() { docker exec "$P" wget -qO- "http://localhost:9090/api/v1/query?query=$1" 2>/dev/null; }
up=0; ng=0
for ((i=0; i<60; i+=5)); do
  up=$(pq up | jq '[.data.result[] | select(.value[1] == "1")] | length')
  ng=$(pq "nginx_connections_active%7Bnode_id%3D%22$NODE%22%7D" | jq '.data.result | length')
  (( ${up:-0} >= 3 && ${ng:-0} >= 1 )) && break; sleep 5
done
check "CEN-up-3-targets ($up)" test "${up:-0}" -ge 3
check "CEN-nginx-series-node ($ng)" test "${ng:-0}" -ge 1
h=$(pq "host_memory_available_bytes%7Bnode_id%3D%22$NODE%22%7D" | jq '.data.result | length')
check "CEN-host-metrics ($h)" test "${h:-0}" -ge 1
finish
