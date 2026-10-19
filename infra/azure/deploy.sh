#!/bin/sh
set -eu

usage() {
  echo "usage: deploy.sh [--apply] RESOURCE_GROUP LOCATION SSH_PUBLIC_KEY_FILE SSH_SOURCE_CIDR" >&2
  exit 64
}

apply=false
if [ "${1:-}" = "--apply" ]; then
  apply=true
  shift
fi
[ "$#" -eq 4 ] || usage

resource_group=$1
location=$2
ssh_key_file=$3
ssh_source_cidr=$4

command -v az >/dev/null 2>&1 || {
  echo "Azure CLI is required." >&2
  exit 69
}
[ -f "$ssh_key_file" ] || {
  echo "SSH public key file does not exist." >&2
  exit 66
}
az account show --output none

if [ "$apply" = false ]; then
  echo "WHAT-IF ONLY: add --apply to create billable Azure resources." >&2
  az group show --name "$resource_group" --output none || {
    echo "The resource group must already exist for a read-only what-if." >&2
    echo "Use --apply to create it and deploy resources." >&2
    exit 66
  }
  az deployment group what-if \
    --resource-group "$resource_group" \
    --template-file "$(dirname "$0")/main.bicep" \
    --parameters sshPublicKey="$(cat "$ssh_key_file")" allowedSshCidr="$ssh_source_cidr"
  exit 0
fi

az group create --name "$resource_group" --location "$location" --output none
az deployment group create \
  --resource-group "$resource_group" \
  --template-file "$(dirname "$0")/main.bicep" \
  --parameters sshPublicKey="$(cat "$ssh_key_file")" allowedSshCidr="$ssh_source_cidr" \
  --output json
