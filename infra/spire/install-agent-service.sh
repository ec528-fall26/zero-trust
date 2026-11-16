#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: install-agent-service.sh SPIRE_SERVER_ADDRESS BOOTSTRAP_BUNDLE" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
server_address=$1
bootstrap_bundle=$2
case "$server_address" in ''|*[!a-zA-Z0-9.:-]*) usage ;; esac
[ -f "$bootstrap_bundle" ] || { echo "bootstrap bundle is unavailable" >&2; exit 66; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 77; }
[ -x /opt/spire/bin/spire-agent ] || { echo "install SPIRE binaries first" >&2; exit 69; }

repository=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
install -d -o root -g root -m 0755 /etc/spire/agent
install -d -o root -g root -m 0700 /var/lib/spire/agent
install -d -o root -g root -m 0755 /run/spire/agent/public
install -o root -g root -m 0644 "$bootstrap_bundle" /etc/spire/agent/bootstrap.pem
install -o root -g root -m 0644 \
  "$repository/infra/spire/agent-aws.conf" /etc/spire/agent/agent.conf

cat > /etc/systemd/system/spire-agent.service <<SERVICE
[Unit]
Description=SPIRE agent for EC528 workload identities
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SPIRE_SERVER_ADDRESS=$server_address
ExecStart=/opt/spire/bin/spire-agent run -expandEnv -config /etc/spire/agent/agent.conf
Restart=on-failure
RestartSec=2
RuntimeDirectory=spire/agent/public
RuntimeDirectoryMode=0755
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/spire/agent /run/spire/agent
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now spire-agent.service
for _attempt in $(seq 1 30); do
  curl --fail --silent --max-time 2 http://127.0.0.1:8082/ready >/dev/null && break
  sleep 1
done
curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8082/ready >/dev/null || {
  journalctl -u spire-agent.service -n 50 --no-pager >&2 || true
  exit 75
}
