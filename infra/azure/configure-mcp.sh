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

ssh "${ssh_args[@]}" "$ssh_user@$host" 'mkdir -p /tmp/ec528-mcp/src/keylime_mcp'
scp "${ssh_args[@]}" "$repository/package.json" "$repository/package-lock.json" "$ssh_user@$host:/tmp/ec528-mcp/"
scp "${ssh_args[@]}" "$repository/src/keylime_mcp/attest_and_deploy.mjs" "$repository/src/keylime_mcp/server.mjs" "$ssh_user@$host:/tmp/ec528-mcp/src/keylime_mcp/"
scp "${ssh_args[@]}" "$token_file" "$ssh_user@$host:/tmp/ec528-mcp-token"

ssh "${ssh_args[@]}" "$ssh_user@$host" 'sudo sh -s' <<'REMOTE'
set -eu
id ec528-mcp >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /sbin/nologin ec528-mcp
rm -rf /opt/ec528-mcp
install -d -o root -g root -m 0755 /opt/ec528-mcp
cp -R /tmp/ec528-mcp/. /opt/ec528-mcp/
cd /opt/ec528-mcp
npm ci --omit=dev --ignore-scripts
chown -R root:root /opt/ec528-mcp
chmod -R go-w /opt/ec528-mcp
install -o root -g ec528-mcp -m 0640 /tmp/ec528-mcp-token /etc/ec528-keylime-mcp-token
cat > /etc/sudoers.d/ec528-keylime-mcp <<'EOF'
ec528-mcp ALL=(root) NOPASSWD: /usr/local/libexec/ec528-keylime-status
EOF
chmod 0440 /etc/sudoers.d/ec528-keylime-mcp
cat > /etc/systemd/system/ec528-keylime-mcp.service <<'EOF'
[Unit]
Description=EC528 receipt-protected Keylime MCP backend
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
Environment=KEYLIME_TARGET=azure-vm-demo-01
Environment=KEYLIME_AGENT_ID=d432fbb3-d2f1-4a97-9ef7-75bd81c00000
Environment=KEYLIME_POLICY_VERSION=demo-2.1
Environment=KEYLIME_MAX_ATTESTATION_AGE_SECONDS=30
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
cat > /usr/local/bin/ec528-keylime-status-sudo <<'EOF'
#!/bin/sh
set -eu
exec sudo /usr/local/libexec/ec528-keylime-status
EOF
chown root:root /usr/local/bin/ec528-keylime-status-sudo
chmod 0755 /usr/local/bin/ec528-keylime-status-sudo
systemctl daemon-reload
systemctl enable --now ec528-keylime-mcp.service
rm -rf /tmp/ec528-mcp /tmp/ec528-mcp-token
curl --fail --silent http://127.0.0.1:3000/healthz
REMOTE

echo "MCP configured. Start the tunnel with:"
echo "ssh -N -L 3000:127.0.0.1:3000 $ssh_user@$host"
echo "Then export KEYLIME_MCP_URL=http://127.0.0.1:3000/mcp"
echo "and KEYLIME_MCP_TOKEN from $token_file"
