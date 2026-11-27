#!/usr/bin/env bash
# Node bootstrap (5.4): build the release, install it in a clean ubuntu:24.04 container
# (no systemd, no Docker: a `docker compose version` shim stands in for the engine check),
# then wafctl node bootstrap + wafctl validate; the config repo has exactly one commit.
set -uo pipefail
source "$(dirname "$0")/lib.sh"
VER="0.0.0-e2e"
TGZ=$("$ROOT/scripts/build-release.sh" "$VER") || { echo "FAIL build-release"; exit 1; }
check "BS-release-built" test -s "$TGZ"
check "BS-release-no-secrets" bash -c "! tar tzf '$TGZ' | grep -E '\.key$|secrets\.env|tokens\.json|\.pem$|/plans/'"
out=$(docker run --rm -i -v "$TGZ:/tmp/rel.tgz:ro" ubuntu:24.04 bash -s <<'IN' 2>&1
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq git >/dev/null
cd /tmp && tar xzf rel.tgz
# without docker the installer must refuse
if nginx-aws-waf-*/scripts/install-node.sh >/tmp/nodocker.out 2>&1; then echo "NODOCKER=accepted"; else echo "NODOCKER=refused $(grep -c docs.docker.com /tmp/nodocker.out)"; fi
printf '#!/bin/sh\n[ "$1 $2" = "compose version" ] && echo "Docker Compose version v2-shim" && exit 0\nexit 1\n' > /usr/local/bin/docker
chmod +x /usr/local/bin/docker
nginx-aws-waf-*/scripts/install-node.sh
echo "VERSION=$(wafctl version)"
cd /
wafctl node bootstrap --node-id t1 --role node --central central.example.com
echo "VALIDATE_RC=$(wafctl validate >/tmp/v.out 2>&1; echo $?)"
cat /tmp/v.out
echo "COMMITS=$(git -C /etc/waf-node log --oneline | wc -l)"
echo "TRACKED=$(git -C /etc/waf-node ls-files | tr '\n' ' ')"
echo "SECRETS_MODE=$(stat -c %a /etc/waf-node/secrets.env)"
echo "CERTDIR_MODE=$(stat -c %a /srv/waf/certs/_node)"
echo "AGAIN_RC=$(wafctl node bootstrap --node-id t1 --role node >/dev/null 2>&1; echo $?)"
IN
)
echo "$out" | sed 's/^/  | /'
v() { sed -n "s/^$1=//p" <<<"$out" | tail -1; }
check "BS-install-refuses-without-docker" test "$(v NODOCKER)" = "refused 1"
check "BS-installed-version" test "$(v VERSION)" = "wafctl $VER"
check "BS-validate-rc0" test "$(v VALIDATE_RC)" = 0
check "BS-one-commit" test "$(v COMMITS)" = 1
check "BS-tracked-no-secrets" bash -c "t='$(v TRACKED)'; [[ \$t == *node.yaml* && \$t == *.gitignore* && \$t != *secrets.env* ]]"
check "BS-secrets-0600" test "$(v SECRETS_MODE)" = 600
check "BS-certdir-0700" test "$(v CERTDIR_MODE)" = 700
check "BS-second-run-refused" test "$(v AGAIN_RC)" = 1
finish
