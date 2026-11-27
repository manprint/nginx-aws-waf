#!/usr/bin/env bash
# Alerts (4.3): provisioned rules healthy (T-AL3), contact point → apprise → alert-sink (T-AL4),
# a real block spike fires "WAF block spike" end to end (T-AL5). Needs the lab with profile test
# (alert-sink) and lab/config/central.yaml (block_spike_per_5m: 20).
set -uo pipefail
source "$(dirname "$0")/lib.sh"
SECRETS="${WAF_CONFIG_DIR:-$ROOT/lab/config}/secrets.env"
PW="${GF_ADMIN_PASSWORD:-$(sed -n 's/^GF_ADMIN_PASSWORD=//p' "$SECRETS")}"
GU="${WAF_GRAFANA_URL:-http://127.0.0.1:3000}"
SINK="${WAF_COMPOSE_PROJECT:-waf}-alert-sink-1"
OHA="$(command -v oha || echo "$HOME/.cargo/bin/oha")"
g() { curl -s -u "admin:$PW" -H 'Content-Type: application/json' "$@"; }
sinklog() { docker logs "$SINK" 2>&1 | grep '^ALERT-SINK'; }
for ((i=0; i<60; i++)); do [[ "$(g "$GU/api/health" | jq -r .database 2>/dev/null)" == ok ]] && break; sleep 2; done

# T-AL3: 5 rules, none with health error (wait for the first evaluation)
for ((i=0; i<12; i++)); do
  rules=$(g "$GU/api/prometheus/grafana/api/v1/rules" | jq -c '[.data.groups[] | select(.name == "waf") | .rules[] | {name, health, lastError}]')
  n=$(jq length <<<"$rules"); bad=$(jq '[.[] | select(.health == "error" or .health == "unknown")] | length' <<<"$rules")
  (( n == 5 && bad == 0 )) && break; sleep 5
done
check "T-AL3 5 rules, none in error (n=$n bad=$bad)" test "$n" = 5 -a "$bad" = 0
(( bad > 0 )) && jq -c '.[] | select(.health != "ok")' <<<"$rules"

# T-AL4: receiver test → apprise → alert-sink
R="$GU/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers"
uid=$(g "$R" | jq -r '.items[] | select(.spec.title == "apprise") | .metadata.name')
integ=$(g "$R/$uid" | jq -c '.spec.integrations[0]')
before=$(sinklog | wc -l)
res=$(g -X POST "$R/$uid/test" -d "{\"integration\":$integ}" | jq -r .status)
for ((i=0; i<15; i++)); do sinklog | tail -n +$((before+1)) | grep -q '"title": "\[WAF\] ' && break; sleep 1; done
check "T-AL4 contact point test delivered ($res)" bash -c "docker logs '$SINK' 2>&1 | grep '^ALERT-SINK' | tail -n +$((before+1)) | grep -q '\"title\": \"\[WAF\] '"

# T-AL5: 300 blocked requests on demo → WAF block spike within 4 min. oha cannot drop the
# User-Agent header (-H 'User-Agent:' still sends oha's), so the spike uses an XSS query
# argument (CrossSiteScripting_QUERYARGUMENTS) instead of NoUserAgent_HEADER.
before=$(sinklog | wc -l)
U="$WAF_URL/al5-spike?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
"$OHA" -n 300 -c 10 --no-tui -H 'Host: demo.lab.test' "$U" >/dev/null 2>&1 \
  || for i in $(seq 300); do curl -s -o /dev/null -H 'Host: demo.lab.test' "$U"; done
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: demo.lab.test' "$U")
check "T-AL5 spike requests are blocked ($code)" test "$code" = 403
fired=no
for ((i=0; i<48; i++)); do
  if sinklog | tail -n +$((before+1)) | grep -q '"title": "\[WAF\] WAF block spike"'; then fired=yes; break; fi
  sleep 5
done
check "T-AL5 WAF block spike delivered (after $((i*5)) s)" test "$fired" = yes
[[ "$fired" == yes ]] && sinklog | tail -n +$((before+1)) | grep -m1 'WAF block spike' | cut -c1-300
finish
