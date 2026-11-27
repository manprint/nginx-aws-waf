#!/usr/bin/env bash
# Build the release tarball: build/nginx-aws-waf-VERSION.tar.gz (top dir nginx-aws-waf-VERSION/).
# Contents: wafctl (linux/amd64, CGO off, version stamped), waf/, deploy/, profiles/,
# scripts/{fetch-ip-lists.sh,install-node.sh}, docs/ (without the plans).
set -euo pipefail
VERSION="${1:?usage: scripts/build-release.sh VERSION}"
[[ "$VERSION" =~ ^[0-9A-Za-z._-]+$ ]] || { echo "bad VERSION: $VERSION" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="nginx-aws-waf-$VERSION"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/$NAME"
mkdir -p "$D/scripts" "$ROOT/build"
(cd "$ROOT/wafctl" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X nginxawswaf/wafctl/internal/version.Version=$VERSION" -o "$D/wafctl" ./cmd/wafctl)
cp -a "$ROOT/waf" "$ROOT/deploy" "$ROOT/profiles" "$D/"
rsync -a --exclude plans "$ROOT/docs/" "$D/docs/"
cp "$ROOT/scripts/fetch-ip-lists.sh" "$ROOT/scripts/install-node.sh" "$D/scripts/"
cp "$ROOT/README.md" "$D/"
# nothing secret or generated may ship
if find "$D" \( -name '*.key' -o -name 'secrets.env*' -o -name 'tokens.json' -o -name '*.pem' \) | grep -q .; then
  echo "refusing: secret-looking files in the release" >&2; exit 1
fi
tar -C "$STAGE" --owner=0 --group=0 --sort=name -czf "$ROOT/build/$NAME.tar.gz" "$NAME"
echo "$ROOT/build/$NAME.tar.gz"
