#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root on the Keylime node" >&2; exit 77; }
[ -c /dev/tpmrm0 ] || { echo "no kernel hardware TPM resource manager device" >&2; exit 66; }
[ -n "$(head -c 64 /sys/kernel/security/tpm0/binary_bios_measurements | od -An -tx1)" ] || {
  echo "no non-empty UEFI measured-boot event log" >&2
  exit 66
}
[ "$(cat /var/lib/ec528-bootstrap-result 2>/dev/null || true)" = keylime-bootstrap-pending ] || {
  echo "switch TPM mode before quorum-controlled tenant enrollment" >&2
  exit 65
}

systemctl stop keylime_agent.service
install -d -o root -g root -m 0700 /var/lib/ec528/swtpm-dropins-disabled
for dropin in \
  /etc/systemd/system/keylime_agent.service.d/10-swtpm.conf \
  /etc/systemd/system/keylime_agent.service.d/20-ima-emulator.conf; do
  if [ -f "$dropin" ]; then
    mv "$dropin" /var/lib/ec528/swtpm-dropins-disabled/
  fi
done
cat > /etc/systemd/system/keylime_agent.service.d/10-hardware-tpm.conf <<'UNIT'
[Service]
Environment="TCTI=device:/dev/tpmrm0"
UNIT
systemctl disable --now ec528-ima-emulator.service swtpm-keylime.service
systemctl daemon-reload
# The registrar still holds the swtpm identity for this UUID and refuses a
# re-registration with a different TPM; the AK in agent_data.json also belongs
# to swtpm.  Remove both so the agent registers the hardware TPM's EK and AK.
keylime_tenant -c regdelete -u "${KEYLIME_AGENT_UUID:-d432fbb3-d2f1-4a97-9ef7-75bd81c00000}" >/dev/null 2>&1 || true
if [ -f /var/lib/keylime/agent_data.json ]; then
  mv /var/lib/keylime/agent_data.json /var/lib/ec528/swtpm-dropins-disabled/agent_data.json
fi
printf '%s\n' nitrotpm > /var/lib/ec528/hardware-tpm-active
chmod 0600 /var/lib/ec528/hardware-tpm-active
systemctl start keylime_agent.service
systemctl is-active --quiet keylime_agent.service
echo "hardware TPM and measured-boot log enabled; run the quorum bootstrap next"
