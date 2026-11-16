#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: register-workload.sh PARENT_SPIFFE_ID WORKLOAD_SPIFFE_ID UNIX_UID" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage
parent_id=$1
workload_id=$2
workload_uid=$3
case "$parent_id" in spiffe://zt.demo/*) ;; *) usage ;; esac
case "$workload_id" in spiffe://zt.demo/*) ;; *) usage ;; esac
case "$workload_uid" in ''|*[!0-9]*) usage ;; esac
[ "$workload_uid" -le 4294967295 ] || usage

spire_server=${SPIRE_SERVER_BINARY:-/opt/spire/bin/spire-server}
socket_path=${SPIRE_SERVER_SOCKET:-/run/spire/server/private/api.sock}
[ -x "$spire_server" ] || { echo "SPIRE server CLI is unavailable" >&2; exit 69; }
[ -S "$socket_path" ] || { echo "SPIRE server socket is unavailable" >&2; exit 75; }

existing=$($spire_server entry show \
  -socketPath "$socket_path" \
  -spiffeID "$workload_id" \
  -output json)
count=$(printf '%s' "$existing" | python3 -c 'import json,sys; value=json.load(sys.stdin); print(len(value.get("entries", [])))')
case "$count" in
  0)
    exec "$spire_server" entry create \
      -socketPath "$socket_path" \
      -parentID "$parent_id" \
      -spiffeID "$workload_id" \
      -selector "unix:uid:$workload_uid" \
      -x509SVIDTTL 300
    ;;
  1)
    echo "registration already exists: $workload_id"
    ;;
  *)
    echo "refusing ambiguous registration entries for $workload_id" >&2
    exit 65
    ;;
esac
