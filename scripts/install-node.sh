#!/usr/bin/env bash
# Install a nginx-aws-waf release on Ubuntu 22.04/24.04 (run as root from the unpacked tarball):
#   tar xzf nginx-aws-waf-VERSION.tar.gz && sudo nginx-aws-waf-VERSION/scripts/install-node.sh
# Copies the release to $WAF_HOME (default /opt/nginx-aws-waf) and links wafctl into /usr/local/bin.
# Docker is not installed here: see https://docs.docker.com/engine/install/ubuntu/
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
WAF_HOME="${WAF_HOME:-/opt/nginx-aws-waf}"
[[ $(id -u) -eq 0 ]] || { echo "install-node.sh: run as root" >&2; exit 1; }
if ! docker compose version >/dev/null 2>&1; then
  echo "install-node.sh: docker compose not found. Install Docker Engine + the compose plugin first:" >&2
  echo "  https://docs.docker.com/engine/install/ubuntu/  (or: apt-get install docker.io docker-compose-v2)" >&2
  exit 1
fi
command -v git >/dev/null || { echo "install-node.sh: git not found (apt-get install git)" >&2; exit 1; }
[[ -x "$SRC/wafctl" && -f "$SRC/waf/catalog/rules.yaml" ]] || { echo "install-node.sh: $SRC is not an unpacked release" >&2; exit 1; }
if [[ "$SRC" != "$WAF_HOME" ]]; then
  mkdir -p "$WAF_HOME"
  cp -a "$SRC/." "$WAF_HOME/"
fi
ln -sf "$WAF_HOME/wafctl" /usr/local/bin/wafctl
echo "installed $("$WAF_HOME/wafctl" version 2>/dev/null || echo wafctl) in $WAF_HOME"
cat <<EOF
next: create the node configuration (git repo in \$WAF_CONFIG_DIR, default /etc/waf-node):
  WAF_HOME=$WAF_HOME wafctl node bootstrap --node-id <id> --role node --central <central-host> --install-systemd
EOF
