#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "usage: configure-mcp.sh VM_HOST [SSH_USER] [SSH_KEY_FILE]" >&2
  exit 64
fi

host=$1
ssh_user=${2:-ec528admin}
ssh_key=${3:-}
repository=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
state_directory="$repository/build/azure-keylime"
mkdir -p "$state_directory"
chmod 700 "$state_directory"
token_file="$state_directory/mcp-token"
if [ ! -f "$token_file" ]; then
  umask 077
  openssl rand -hex 32 > "$token_file"
fi

ssh_args=(-o StrictHostKeyChecking=accept-new)
if [ -n "$ssh_key" ]; then
  ssh_args+=(-i "$ssh_key")
fi

ssh "${ssh_args[@]}" "$ssh_user@$host" \
  'mkdir -p /tmp/ec528-mcp/src/keylime_mcp /tmp/ec528-mcp/config'
scp "${ssh_args[@]}" "$repository/package.json" "$repository/package-lock.json" "$ssh_user@$host:/tmp/ec528-mcp/"
scp "${ssh_args[@]}" \
  "$repository/src/keylime_mcp/attest_and_deploy.mjs" \
  "$repository/src/keylime_mcp/bootstrap_tenant.mjs" \
  "$repository/src/keylime_mcp/config.mjs" \
  "$repository/src/keylime_mcp/policy_digest.mjs" \
  "$repository/src/keylime_mcp/server.mjs" \
  "$ssh_user@$host:/tmp/ec528-mcp/src/keylime_mcp/"
scp "${ssh_args[@]}" \
  "$repository/src/security_parameters.mjs" \
  "$ssh_user@$host:/tmp/ec528-mcp/src/"
scp "${ssh_args[@]}" \
  "$repository/config/security-parameters.json" \
  "$ssh_user@$host:/tmp/ec528-mcp/config/"
scp "${ssh_args[@]}" "$token_file" "$ssh_user@$host:/tmp/ec528-mcp-token"

ssh "${ssh_args[@]}" "$ssh_user@$host" 'sudo sh -s' <<'REMOTE'
set -eu
id ec528-mcp >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /sbin/nologin ec528-mcp
rm -rf /opt/ec528-mcp
install -d -o root -g root -m 0755 /opt/ec528-mcp
cp -R /tmp/ec528-mcp/. /opt/ec528-mcp/
cd /opt/ec528-mcp
npm ci --omit=dev --ignore-scripts
attestation_max_age=$(node -e \
  'const p=require("./config/security-parameters.json"); process.stdout.write(String(p.attestation_max_age_sec))')
fresh_attestation_timeout=$(node -e \
  'const p=require("./config/security-parameters.json"); process.stdout.write(String(p.fresh_attestation_timeout_sec))')
chown -R root:root /opt/ec528-mcp
chmod -R go-w /opt/ec528-mcp
install -o root -g ec528-mcp -m 0640 /tmp/ec528-mcp-token /etc/ec528-keylime-mcp-token
rm -f /usr/local/bin/ec528-keylime-status-sudo /etc/sudoers.d/ec528-keylime-mcp
cat > /etc/systemd/system/ec528-keylime-status.socket <<'EOF'
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
EOF
cat > /etc/systemd/system/ec528-keylime-status@.service <<'EOF'
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
EOF
cat > /etc/systemd/system/ec528-keylime-mcp.service <<EOF
[Unit]
Description=EC528 receipt-protected Keylime MCP backend
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
Environment=KEYLIME_TARGET=azure-vm-demo-01
Environment=KEYLIME_AGENT_ID=d432fbb3-d2f1-4a97-9ef7-75bd81c00000
Environment=KEYLIME_POLICY_VERSION=demo-2.1
Environment=KEYLIME_MAX_ATTESTATION_AGE_SECONDS=$attestation_max_age
Environment=KEYLIME_REQUIRE_FRESH_ATTESTATION=0
Environment=KEYLIME_FRESH_ATTESTATION_TIMEOUT_SECONDS=$fresh_attestation_timeout
ExecStart=/usr/bin/node /opt/ec528-mcp/src/keylime_mcp/server.mjs
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
EOF
systemctl daemon-reload
systemctl enable --now ec528-keylime-status.socket
systemctl enable --now ec528-keylime-mcp.service
rm -rf /tmp/ec528-mcp /tmp/ec528-mcp-token
curl --fail --silent http://127.0.0.1:3000/healthz
REMOTE

echo "MCP configured. Start the tunnel with:"
echo "ssh -N -L 3000:127.0.0.1:3000 $ssh_user@$host"
echo "Then export KEYLIME_MCP_URL=http://127.0.0.1:3000/mcp"
echo "and KEYLIME_MCP_TOKEN from $token_file"
