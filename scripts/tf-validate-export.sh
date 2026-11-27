#!/usr/bin/env bash
# terraform init -backend=false + validate (+ fmt -check) of an export-aws --format terraform file,
# in a temp dir with the pinned terraform image (same pin as make tf-validate). Never planned/applied.
# Prints VALID on "Success!". Provider downloads are cached in build/.tf-plugin-cache.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
f="${1:?usage: scripts/tf-validate-export.sh FILE.tf}"
[[ -r "$f" ]] || { echo "not readable: $f" >&2; exit 2; }
TF_IMAGE="${TF_IMAGE:-$(sed -n 's/^TF_IMAGE := //p' "$ROOT/Makefile")}"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
cp "$f" "$d/main.tf"
cache="$ROOT/build/.tf-plugin-cache"; mkdir -p "$cache"
tf() { docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e TF_PLUGIN_CACHE_DIR=/cache -e TF_IN_AUTOMATION=1 \
  -v "$d:/tf" -v "$cache:/cache" -w /tf "$TF_IMAGE" "$@"; }
out=$(tf init -backend=false -input=false 2>&1) || { echo "$out"; echo "INVALID (init)"; exit 1; }
out=$(tf validate -no-color 2>&1); rc=$?
if [[ $rc -ne 0 ]] || ! grep -q 'Success!' <<<"$out"; then echo "$out"; echo "INVALID (validate)"; exit 1; fi
fmt=$(tf fmt -check -diff -no-color main.tf 2>&1) || { echo "$fmt"; echo "INVALID (fmt)"; exit 1; }
echo VALID
