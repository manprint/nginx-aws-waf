#!/usr/bin/env bash
# nginx -t on a rendered runtime dir inside the engine image (G-NGXT).
# usage: scripts/ngx-test.sh [--modsec-only] <runtime-dir>
#   <runtime-dir> basename must be the rev; it is mounted at /etc/waf/runtime/<rev>.
#   --modsec-only: only modsec/main.conf is required; a minimal nginx.conf is generated.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
modsec_only=0
if [[ "${1:-}" == "--modsec-only" ]]; then modsec_only=1; shift; fi
dir="$(cd "${1:?usage: ngx-test.sh [--modsec-only] <runtime-dir>}" && pwd)"
rev="$(basename "$dir")"
img="${WAF_IMAGE:-ghcr.io/manprint/nginx-aws-waf/waf:latest}"
docker image inspect "$img" >/dev/null 2>&1 || img="owasp/modsecurity-crs:4.30.0-nginx-alpine-202611190211"
lists="${WAF_DATA_DIR:-$here/.run}/lists"
[[ -d "$lists" ]] || { echo "missing $lists (run: make lists)" >&2; exit 2; }
R="/etc/waf/runtime/$rev"
certs="${WAF_DATA_DIR:-$here/.run}/certs"
args=(--rm --user root -v "$lists:/etc/waf/lists:ro")
if (( modsec_only )); then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/$rev/modsec" "$tmp/$rev/nginx" "$tmp/$rev/data"
  cp "$dir/modsec/main.conf" "$tmp/$rev/modsec/"
  if [[ -d "$dir/data" ]]; then cp "$dir"/data/* "$tmp/$rev/data/"; else cp "$here"/waf/data/*.data "$tmp/$rev/data/"; fi
  [[ -d "$dir/modsec/sites" ]] && cp -r "$dir/modsec/sites" "$tmp/$rev/modsec/"
  site_inc=""; port=9000
  for f in "$tmp/$rev"/modsec/sites/*.conf; do
    [[ -e "$f" ]] || continue
    n="$(basename "$f" .conf)"
    site_inc+="  server { listen 127.0.0.1:$((port++)); server_name $n; modsecurity_rules_file $R/modsec/sites/$n.conf; location / { proxy_pass http://127.0.0.1:8081; } }"$'\n'
  done
  cat > "$tmp/$rev/nginx/nginx.conf" <<NGX
load_module modules/ngx_http_modsecurity_module.so;
pid /tmp/nginx.pid; error_log /dev/stderr warn;
events {}
http {
  server { listen 127.0.0.1:8081; modsecurity off; location / { return 200 ok; } }
  modsecurity on; modsecurity_rules_file $R/modsec/main.conf;
  server { listen 8080; location / { proxy_pass http://127.0.0.1:8081; } }
$site_inc}
NGX
  dir="$tmp/$rev"
else
  logs="$(mktemp -d)"; trap 'rm -rf "$logs"' EXIT
  args+=(-v "$logs:/var/log/waf")
  [[ -d "$certs" ]] && args+=(-v "$certs:/etc/waf/certs:ro")
  docker network inspect waf_lab >/dev/null 2>&1 && args+=(--network waf_lab)
  for h in $(grep -ho 'server [A-Za-z0-9._-]*:[0-9]*' "$dir"/nginx/sites/*.conf 2>/dev/null | awk '{print $2}' | cut -d: -f1 | sort -u); do
    [[ "$h" =~ ^[0-9.]+$ ]] || docker network inspect waf_lab >/dev/null 2>&1 || args+=(--add-host "$h:127.0.0.1")
  done
fi
args+=(-v "$dir:$R:ro" --entrypoint nginx "$img" -t -c "$R/nginx/nginx.conf")
docker run "${args[@]}"
