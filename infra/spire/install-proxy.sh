#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: install-proxy.sh client|server SERVICE_USER EXPECTED_PEER_SPIFFE_ID TARGET TOKEN_FILE" >&2
  exit 64
}

[ "$#" -eq 5 ] || usage
role=$1
service_user=$2
expected_peer_id=$3
target=$4
token_file=$5

case "$role" in client|server) ;; *) usage ;; esac
case "$service_user" in ''|*[!a-zA-Z0-9_-]*) usage ;; esac
case "$expected_peer_id" in spiffe://zt.demo/*) ;; *) usage ;; esac
case "$target" in
  https://*) [ "$role" = client ] || usage ;;
  http://127.0.0.1:*) [ "$role" = server ] || usage ;;
  *) usage ;;
esac
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 77; }
id "$service_user" >/dev/null 2>&1 || { echo "service user does not exist" >&2; exit 67; }
[ -f "$token_file" ] || { echo "token file does not exist" >&2; exit 66; }
token_mode=$(stat -c '%a' "$token_file")
token_mode_value=$((8#$token_mode))
[ $((token_mode_value & 077)) -eq 0 ] || {
  echo "token file permissions are too broad" >&2
  exit 65
}

repository=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
proxy="$repository/src/spire/mtls_proxy.mjs"
[ -f "$proxy" ] || { echo "SPIFFE proxy source is unavailable" >&2; exit 69; }
command -v node >/dev/null 2>&1 || { echo "node is required" >&2; exit 69; }
command -v spiffe-helper >/dev/null 2>&1 || { echo "spiffe-helper is required" >&2; exit 69; }

install -d -o "$service_user" -g "$service_user" -m 0700 /run/ec528-spiffe
install -d -o root -g root -m 0755 /etc/ec528-spiffe
install -o root -g root -m 0644 "$repository/infra/spire/helper.conf" /etc/ec528-spiffe/helper.conf

listen_port=3001
target_name=SPIFFE_PROXY_UPSTREAM
token_name=SPIFFE_PROXY_LOCAL_TOKEN_FILE
if [ "$role" = server ]; then
  listen_port=3443
  target_name=SPIFFE_PROXY_BACKEND
  token_name=SPIFFE_PROXY_BACKEND_TOKEN_FILE
fi

umask 077
environment_file=/etc/ec528-spiffe/proxy.env
{
  printf 'SPIFFE_PROXY_MODE=%s\n' "$role"
  printf 'SPIFFE_PROXY_LISTEN_PORT=%s\n' "$listen_port"
  printf 'SPIFFE_PROXY_EXPECTED_PEER_ID=%s\n' "$expected_peer_id"
  printf 'SPIFFE_PROXY_CERT_FILE=/run/ec528-spiffe/svid.pem\n'
  printf 'SPIFFE_PROXY_KEY_FILE=/run/ec528-spiffe/svid_key.pem\n'
  printf 'SPIFFE_PROXY_BUNDLE_FILE=/run/ec528-spiffe/svid_bundle.pem\n'
  printf '%s=%s\n' "$target_name" "$target"
  printf '%s=%s\n' "$token_name" "$token_file"
} > "$environment_file"
chown root:"$service_user" "$environment_file"
chmod 0640 "$environment_file"

cat > /etc/systemd/system/ec528-spiffe-helper.service <<SERVICE
[Unit]
Description=EC528 SPIFFE SVID rotation helper
After=spire-agent.service
Requires=spire-agent.service

[Service]
Type=simple
User=$service_user
Group=$service_user
ExecStart=/usr/local/bin/spiffe-helper -config /etc/ec528-spiffe/helper.conf
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/ec528-spiffe
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
SERVICE

cat > /etc/systemd/system/ec528-spiffe-proxy.service <<SERVICE
[Unit]
Description=EC528 SPIFFE mTLS $role proxy
After=ec528-spiffe-helper.service
Requires=ec528-spiffe-helper.service

[Service]
Type=simple
User=$service_user
Group=$service_user
EnvironmentFile=$environment_file
ExecStart=/usr/bin/node $proxy
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now ec528-spiffe-helper.service

for _attempt in $(seq 1 30); do
  [ -s /run/ec528-spiffe/svid.pem ] && \
    [ -s /run/ec528-spiffe/svid_key.pem ] && \
    [ -s /run/ec528-spiffe/svid_bundle.pem ] && break
  sleep 1
done
[ -s /run/ec528-spiffe/svid.pem ] && \
  [ -s /run/ec528-spiffe/svid_key.pem ] && \
  [ -s /run/ec528-spiffe/svid_bundle.pem ] || {
    echo "SPIFFE workload identity was not issued" >&2
    journalctl -u ec528-spiffe-helper.service -n 50 --no-pager >&2 || true
    exit 75
  }

systemctl enable --now ec528-spiffe-proxy.service
if [ "$role" = client ]; then
  exec 3< <(printf 'Authorization: Bearer %s\n' "$(cat "$token_file")")
  curl --fail --silent --show-error --max-time 5 \
    --header @/dev/fd/3 \
    "http://127.0.0.1:${listen_port}/healthz" >/dev/null || {
      exec 3<&-
      echo "SPIFFE proxy health check failed closed" >&2
      journalctl -u ec528-spiffe-proxy.service -n 50 --no-pager >&2 || true
      exit 75
    }
  exec 3<&-
else
  sleep 1
  systemctl is-active --quiet ec528-spiffe-proxy.service || {
    echo "SPIFFE server proxy did not stay active" >&2
    journalctl -u ec528-spiffe-proxy.service -n 50 --no-pager >&2 || true
    exit 75
  }
fi
