#!/usr/bin/env bash
# Scarica il sorgente OWASP CRS (stessa versione inclusa nell'immagine Docker) in vendor/,
# come riferimento per scegliere/adattare le regole da riusare nella simulazione.
set -euo pipefail

CRS_VERSION="${CRS_VERSION:-4.30.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/vendor/coreruleset"

rm -rf "$DEST"; mkdir -p "$DEST"
curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
  | tar -xz -C "$DEST" --strip-components=1
echo "ok    OWASP CRS v${CRS_VERSION} -> vendor/coreruleset ($(ls "$DEST/rules"/*.conf | wc -l) file di regole)"
