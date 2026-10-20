#!/usr/bin/env bash
# Rebuild the local Keylime development environment directly on AlmaLinux 10
# (native install or inside WSL). Run from the repository root:
#   sudo bash ./scripts/setup-keylime-dev.sh
#
# DEVELOPMENT ONLY: the node uses a software TPM (swtpm), so attestation is
# not tied to a hardware root of trust. The final evaluation runs on MOC.
#
# Pinned versions (AlmaLinux 10.2 AppStream, checked 2026-09-30):
#   keylime 7.14.1, keylime-agent-rust 0.2.9, swtpm 0.9.0, tpm2-tools 5.7
#
# Safe to rerun: every step skips work that is already done.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  exec sudo bash "$0" "$@"
fi

AGENT_UUID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"   # Keylime agent default UUID

[ -d /run/systemd/system ] || { echo "systemd is not running; Keylime needs it." >&2; exit 1; }

# Retry a check once per second for up to 30 seconds.
wait_for() {
  local what=$1; shift
  for _ in $(seq 1 30); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "Timed out waiting for $what" >&2
  return 1
}
port_open() { bash -c "echo > /dev/tcp/127.0.0.1/$1"; }

# 1. Packages.
dnf install -y keylime keylime-agent-rust swtpm swtpm-tools tpm2-tools

# 2. Software TPM state with endorsement key certificates (created once).
if [ ! -f /var/lib/swtpm/keylime/tpm2-00.permall ]; then
  mkdir -p /var/lib/swtpm/keylime
  chown tss:tss /var/lib/swtpm/keylime
  sudo -u tss swtpm_setup --tpm2 --tpmstate /var/lib/swtpm/keylime \
    --create-ek-cert --create-platform-cert --lock-nvram
fi

# A hand-started swtpm (e.g. "sudo swtpm socket ... &") would hold port 2321
# and block the service, so stop any that isn't the service.
if ! systemctl is-active --quiet swtpm-keylime; then
  pkill -x swtpm || true
fi

# 3. Software TPM as a service, listening only on localhost.
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

# Point the Keylime agent at the software TPM instead of /dev/tpm0.
mkdir -p /etc/systemd/system/keylime_agent.service.d
cat > /etc/systemd/system/keylime_agent.service.d/10-swtpm.conf <<'EOF'
[Unit]
Requires=swtpm-keylime.service
After=swtpm-keylime.service keylime_registrar.service

[Service]
Environment="TCTI=swtpm:host=127.0.0.1,port=2321"
EOF

# Let the tenant trust the software TPM's endorsement key certificate.
install -d /var/lib/keylime/tpm_cert_store
cp /var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem \
   /var/lib/swtpm-localca/issuercert.pem \
   /var/lib/keylime/tpm_cert_store/

# 4. Start services in order.
systemctl daemon-reload
systemctl enable --now swtpm-keylime
wait_for "software TPM (port 2321)" port_open 2321
# The verifier creates the shared certificate authority, so it starts first.
systemctl enable --now keylime_verifier
wait_for "verifier (port 8881)" port_open 8881
systemctl enable --now keylime_registrar
wait_for "registrar (port 8891)" port_open 8891
# Restart (not just start) so an agent stuck in a crash loop picks up the TPM settings.
systemctl enable keylime_agent
systemctl restart keylime_agent
wait_for "agent (port 9002)" port_open 9002

# 5. Enroll the agent with the verifier.
#    keylime_tenant prints its results through its logger (stderr), so merge streams.
cvstatus() { keylime_tenant -c cvstatus -u "$AGENT_UUID" 2>&1 || true; }
state=$(cvstatus | grep -o '"operational_state": "[^"]*"' | tail -1 | cut -d'"' -f4 || true)
add_agent() { keylime_tenant -c add -u "$AGENT_UUID" -t 127.0.0.1 -v 127.0.0.1; }

case "$state" in
  "")
    # Not known to the verifier yet.
    add_agent ;;
  Failed|Terminated|"Invalid Quote"|"Tenant Quote Failed")
    # Enrolled, but the verifier gave up on it (e.g. the agent restarted
    # with a new TPM). Remove the stale entry and enroll again.
    echo "Agent $AGENT_UUID is in state '$state'; re-enrolling."
    keylime_tenant -c delete -u "$AGENT_UUID"
    wait_for "verifier to forget the agent" bash -c \
      "! keylime_tenant -c cvstatus -u $AGENT_UUID 2>&1 | grep -q operational_state"
    add_agent ;;
  *)
    # Start, Get Quote, Get Quote (retry), Provide V, ... : the verifier is
    # already working with this agent, so adding it again would conflict.
    echo "Agent $AGENT_UUID is already enrolled (state: $state)." ;;
esac

# 6. Report the result, waiting up to ~30 s for the first attestation.
result=unknown
for _ in $(seq 1 15); do
  result=$(cvstatus | grep -o '"attestation_status": "[A-Z]*"' | tail -1 | cut -d'"' -f4)
  [ -n "$result" ] && [ "$result" != PENDING ] && break
  sleep 2
done
echo "attestation_status: ${result:-unknown}"
[ "$result" = PASS ]
