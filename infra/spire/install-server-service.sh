#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 77; }
[ -x /opt/spire/bin/spire-server ] || { echo "install SPIRE binaries first" >&2; exit 69; }

repository=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
id spire-server >/dev/null 2>&1 || \
  useradd --system --home-dir /var/lib/spire/server --shell /sbin/nologin spire-server
install -d -o root -g root -m 0755 /etc/spire/server /run/spire/server/private
install -d -o spire-server -g spire-server -m 0700 /var/lib/spire/server
chown spire-server:spire-server /run/spire/server/private
chmod 0700 /run/spire/server/private
install -o root -g root -m 0644 \
  "$repository/infra/spire/server-aws.conf" /etc/spire/server/server.conf

cat > /etc/systemd/system/spire-server.service <<'SERVICE'
[Unit]
Description=SPIRE server for EC528 workload identities
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=spire-server
Group=spire-server
ExecStart=/opt/spire/bin/spire-server run -config /etc/spire/server/server.conf
Restart=on-failure
RestartSec=2
RuntimeDirectory=spire/server/private
RuntimeDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/spire/server /run/spire/server
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now spire-server.service
for _attempt in $(seq 1 30); do
  curl --fail --silent --max-time 2 http://127.0.0.1:8080/ready >/dev/null && break
  sleep 1
done
curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8080/ready >/dev/null || {
  journalctl -u spire-server.service -n 50 --no-pager >&2 || true
  exit 75
}

/opt/spire/bin/spire-server bundle show \
  -socketPath /run/spire/server/private/api.sock \
  -format pem > /etc/spire/server/bootstrap.pem
chown root:root /etc/spire/server/bootstrap.pem
chmod 0644 /etc/spire/server/bootstrap.pem
echo "SPIRE bootstrap bundle: /etc/spire/server/bootstrap.pem"
