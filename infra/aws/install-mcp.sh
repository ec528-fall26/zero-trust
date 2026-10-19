#!/usr/bin/env bash
set -euo pipefail

agent_uuid=${1:-}
case "$agent_uuid" in
  ????????-????-????-????-????????????) ;;
  *) echo "a Keylime agent UUID is required" >&2; exit 64 ;;
esac

for _attempt in $(seq 1 120); do
  if [ "$(cat /var/lib/ec528-bootstrap-result 2>/dev/null || true)" = "keylime-ready" ]; then
    break
  fi
  sleep 5
done
[ "$(cat /var/lib/ec528-bootstrap-result 2>/dev/null || true)" = "keylime-ready" ] || {
  echo "Keylime bootstrap did not become ready" >&2
  exit 75
}

cd /opt/ec528-zero-trust
npm ci --omit=dev --ignore-scripts
chown -R root:root /opt/ec528-zero-trust
chmod -R go-w /opt/ec528-zero-trust

id ec528-mcp >/dev/null 2>&1 || \
  useradd --system --home-dir /nonexistent --shell /sbin/nologin ec528-mcp
umask 077
openssl rand -hex 32 > /etc/ec528-keylime-mcp-token
chown root:ec528-mcp /etc/ec528-keylime-mcp-token
chmod 0640 /etc/ec528-keylime-mcp-token

cat > /usr/local/bin/ec528-keylime-status-sudo <<'SCRIPT'
#!/bin/sh
set -eu
exec sudo /usr/local/libexec/ec528-keylime-status
SCRIPT
chmod 0755 /usr/local/bin/ec528-keylime-status-sudo
printf '%s\n' \
  'ec528-mcp ALL=(root) NOPASSWD: /usr/local/libexec/ec528-keylime-status' \
  > /etc/sudoers.d/ec528-keylime-mcp
chmod 0440 /etc/sudoers.d/ec528-keylime-mcp

cat > /etc/systemd/system/ec528-keylime-mcp.service <<SERVICE
[Unit]
Description=EC528 Keylime MCP backend
After=network-online.target keylime_verifier.service keylime_agent.service
Wants=network-online.target

[Service]
Type=simple
User=ec528-mcp
Group=ec528-mcp
Environment=KEYLIME_MCP_TOKEN_FILE=/etc/ec528-keylime-mcp-token
Environment=KEYLIME_STATUS_COMMAND=/usr/local/bin/ec528-keylime-status-sudo
Environment=KEYLIME_WORKLOAD_ARTIFACT=/opt/ec528/workloads/checksum.sh
Environment=KEYLIME_WORKLOAD_INPUT=/opt/ec528/inputs/demo-payload.txt
Environment=KEYLIME_TARGET=aws-keylime-demo-01
Environment=KEYLIME_AGENT_ID=$agent_uuid
Environment=KEYLIME_POLICY_VERSION=demo-2.1
Environment=KEYLIME_MAX_ATTESTATION_AGE_SECONDS=30
ExecStart=/usr/bin/node /opt/ec528-zero-trust/src/keylime_mcp/server.mjs
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now ec528-keylime-mcp
curl --fail --silent http://127.0.0.1:3000/healthz >/dev/null
printf '%s\n' ready > /var/lib/ec528-bootstrap-result
