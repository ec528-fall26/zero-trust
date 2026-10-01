#!/usr/bin/env bash
# Rebuild the local Keylime development environment in a Lima VM.
# Run from the repository root on macOS: ./scripts/setup-keylime-dev-vm.sh
#
# DEVELOPMENT ONLY: the node uses a software TPM (swtpm), so attestation is
# not tied to a hardware root of trust. The final evaluation runs on MOC.
#
# Pinned versions (AlmaLinux 10.2 AppStream, checked 2026-09-30):
#   keylime 7.14.1, keylime-agent-rust 0.2.9, swtpm 0.9.0, tpm2-tools 5.7
set -euo pipefail

VM="${VM:-keylime}"
AGENT_UUID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"   # Keylime agent default UUID

# 1. Create the VM, or make sure the existing one is running.
if ! limactl list -q | grep -qx "$VM"; then
  limactl start --name="$VM" --tty=false template:almalinux-10
else
  limactl start --tty=false "$VM" >/dev/null 2>&1 || true
fi

# 2. Install and configure everything inside the VM.
limactl shell "$VM" sudo bash -s <<'IN_VM'
set -euo pipefail

dnf install -y keylime keylime-agent-rust swtpm swtpm-tools tpm2-tools

# Software TPM state with endorsement key certificates (created once).
if [ ! -f /var/lib/swtpm/keylime/tpm2-00.permall ]; then
  mkdir -p /var/lib/swtpm/keylime
  chown tss:tss /var/lib/swtpm/keylime
  sudo -u tss swtpm_setup --tpm2 --tpmstate /var/lib/swtpm/keylime \
    --create-ek-cert --create-platform-cert --lock-nvram
fi

# Software TPM as a service, listening only on localhost.
cat > /etc/systemd/system/swtpm-keylime.service <<'EOF'
[Unit]
Description=Software TPM for the Keylime development agent
Before=keylime_agent.service

[Service]
User=tss
Group=tss
ExecStart=/usr/bin/swtpm socket --tpm2 --tpmstate dir=/var/lib/swtpm/keylime --server type=tcp,port=2321,bindaddr=127.0.0.1 --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 --flags not-need-init,startup-clear
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Point the Keylime agent at the software TPM.
mkdir -p /etc/systemd/system/keylime_agent.service.d
cat > /etc/systemd/system/keylime_agent.service.d/10-swtpm.conf <<'EOF'
[Unit]
Requires=swtpm-keylime.service
After=swtpm-keylime.service keylime_registrar.service

[Service]
Environment="TCTI=swtpm:host=127.0.0.1,port=2321"
EOF

# Let the tenant trust the software TPM's endorsement key certificate.
cp /var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem \
   /var/lib/swtpm-localca/issuercert.pem \
   /var/lib/keylime/tpm_cert_store/

systemctl daemon-reload
systemctl enable --now swtpm-keylime
# The verifier creates the shared certificate authority, so it starts first.
systemctl enable --now keylime_verifier
sleep 3
systemctl enable --now keylime_registrar
sleep 3
systemctl enable --now keylime_agent
sleep 3
IN_VM

# 3. Enroll the agent with the verifier unless it is already enrolled.
if limactl shell "$VM" sudo keylime_tenant -c cvstatus -u "$AGENT_UUID" 2>/dev/null \
     | grep -q '"operational_state": "Get Quote"'; then
  echo "Agent $AGENT_UUID is already enrolled."
else
  limactl shell "$VM" sudo keylime_tenant -c add -u "$AGENT_UUID" -t 127.0.0.1 -v 127.0.0.1
  sleep 5
fi

# 4. Report the result.
limactl shell "$VM" sudo keylime_tenant -c cvstatus -u "$AGENT_UUID" 2>/dev/null \
  | grep -o '"attestation_status": "[A-Z]*"'