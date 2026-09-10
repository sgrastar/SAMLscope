#!/usr/bin/env bash
set -euo pipefail

readonly DEPLOY_COMMAND=/opt/samlscope/bin/deploy
readonly ORIGINAL_COMMAND="${SSH_ORIGINAL_COMMAND:-}"

if [[ "$ORIGINAL_COMMAND" =~ ^/opt/samlscope/bin/deploy[[:space:]](ghcr\.io/sgrastar/samlscope@sha256:[0-9a-f]{64})[[:space:]](sha256:[0-9a-f]{64})$ ]]; then
  exec "$DEPLOY_COMMAND" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
fi

echo "Only digest-pinned SAMLscope deployments are allowed for this key." >&2
exit 126
