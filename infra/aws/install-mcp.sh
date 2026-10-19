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

# The MCP runs with NoNewPrivileges=true, so it cannot use sudo.  Instead a
# root-owned helper answers on a socket that only the ec528-mcp group can open.
# Each connection runs the fixed status script once and returns its JSON.
rm -f /usr/local/bin/ec528-keylime-status-sudo /etc/sudoers.d/ec528-keylime-mcp
cat > /etc/systemd/system/ec528-keylime-status.socket <<'UNIT'
[Unit]
Description=EC528 Keylime status helper socket

[Socket]
ListenStream=/run/ec528/keylime-status.sock
SocketUser=root
SocketGroup=ec528-mcp
SocketMode=0660
DirectoryMode=0755
Accept=yes
MaxConnections=8

[Install]
WantedBy=sockets.target
UNIT

cat > /etc/systemd/system/ec528-keylime-status@.service <<'UNIT'
[Unit]
Description=EC528 Keylime status helper (one request)

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/ec528-keylime-status
StandardInput=null
StandardOutput=socket
StandardError=journal
TimeoutStartSec=20
PrivateTmp=true
UNIT

cat > /etc/systemd/system/ec528-keylime-mcp.service <<SERVICE
[Unit]
Description=EC528 Keylime MCP backend
After=network-online.target keylime_verifier.service keylime_agent.service ec528-keylime-status.socket
Wants=network-online.target
Requires=ec528-keylime-status.socket

[Service]
Type=simple
User=ec528-mcp
Group=ec528-mcp
Environment=KEYLIME_MCP_TOKEN_FILE=/etc/ec528-keylime-mcp-token
Environment=KEYLIME_STATUS_SOCKET=/run/ec528/keylime-status.sock
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
systemctl enable --now ec528-keylime-status.socket
systemctl enable --now ec528-keylime-mcp

healthy=false
for _attempt in $(seq 1 30); do
  if curl --fail --silent --max-time 2 http://127.0.0.1:3000/healthz >/dev/null; then
    healthy=true
    break
  fi
  sleep 1
done
if [ "$healthy" != true ]; then
  echo "Keylime MCP did not become healthy" >&2
  journalctl -u ec528-keylime-mcp -n 50 --no-pager >&2 || true
  exit 75
fi

# Exercise the status path the MCP uses, as the MCP user, so a broken helper
# fails the install instead of the first demo request.
if ! runuser -u ec528-mcp -- /usr/bin/python3 -I -c '
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(20)
s.connect("/run/ec528/keylime-status.sock")
data = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    data += chunk
status = json.loads(data)
if status.get("agent_id") != sys.argv[1]:
    raise SystemExit("status helper returned another agent")
print(status["results"].get("attestation_status"))
' "$agent_uuid"; then
  echo "Keylime status helper check failed" >&2
  journalctl -u 'ec528-keylime-status@*' -n 50 --no-pager >&2 || true
  exit 75
fi
printf '%s\n' ready > /var/lib/ec528-bootstrap-result
