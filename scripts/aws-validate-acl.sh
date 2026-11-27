#!/usr/bin/env bash
# Offline validation of an export-aws JSON with the AWS CLI parameter validation (R11): the request
# is built and validated locally, then sent to an unreachable endpoint.
#   exit 255 + "Could not connect" = the input is VALID; exit 252 (or anything else) = INVALID.
# Usage: scripts/aws-validate-acl.sh FILE.json      (CreateWebACL input, export-aws --acl-only)
#        scripts/aws-validate-acl.sh --ip-set FILE.json   (one CreateIPSet input)
# No credentials or profile are used. Without a local aws CLI, the pinned amazon/aws-cli image runs.
set -uo pipefail
op=create-web-acl
[[ "${1:-}" == "--ip-set" ]] && { op=create-ip-set; shift; }
f="${1:?usage: scripts/aws-validate-acl.sh [--ip-set] FILE.json}"
[[ -r "$f" ]] || { echo "not readable: $f" >&2; exit 2; }
AWS_CLI_IMAGE="${AWS_CLI_IMAGE:-amazon/aws-cli:2.35.21}"
args=(wafv2 "$op" --cli-binary-format raw-in-base64-out --endpoint-url http://127.0.0.1:9 --region eu-central-1)
if command -v aws >/dev/null; then
  out=$(env -u AWS_PROFILE -u AWS_SESSION_TOKEN AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x AWS_CONFIG_FILE=/dev/null \
    AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_MAX_ATTEMPTS=1 aws "${args[@]}" --cli-input-json "file://$f" 2>&1); rc=$?
else
  d=$(cd "$(dirname "$f")" && pwd)
  out=$(docker run --rm --network none -e AWS_ACCESS_KEY_ID=x -e AWS_SECRET_ACCESS_KEY=x -e AWS_MAX_ATTEMPTS=1 \
    -v "$d:/w:ro" "$AWS_CLI_IMAGE" "${args[@]}" --cli-input-json "file:///w/$(basename "$f")" 2>&1); rc=$?
fi
if [[ $rc -eq 255 ]] && grep -q 'Could not connect' <<<"$out"; then echo VALID; exit 0; fi
echo "$out"
echo "INVALID (rc=$rc)"
exit 1
