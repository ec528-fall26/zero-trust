#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
output=${1:-"$repository_root/results/demo2-attestation.json"}

: "${KEYLIME_MCP_URL:?KEYLIME_MCP_URL is required}"
: "${KEYLIME_MCP_TOKEN_FILE:?KEYLIME_MCP_TOKEN_FILE is required}"
: "${KEYLIME_ACTION_FILE:?KEYLIME_ACTION_FILE is required}"
: "${KEYLIME_TPM_TYPE:?KEYLIME_TPM_TYPE must state swtpm or nitrotpm}"

case "$KEYLIME_TPM_TYPE" in
  swtpm|nitrotpm) ;;
  *) echo "KEYLIME_TPM_TYPE must be swtpm or nitrotpm" >&2; exit 64 ;;
esac

cd "$repository_root"
exec node experiments/demo2_attestation.mjs "$output"
