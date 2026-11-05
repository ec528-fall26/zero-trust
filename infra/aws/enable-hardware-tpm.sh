#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root on the Keylime node" >&2; exit 77; }
[ -c /dev/tpmrm0 ] || { echo "no kernel hardware TPM resource manager device" >&2; exit 66; }
[ -s /sys/kernel/security/tpm0/binary_bios_measurements ] || {
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
printf '%s\n' nitrotpm > /var/lib/ec528/hardware-tpm-active
chmod 0600 /var/lib/ec528/hardware-tpm-active
systemctl start keylime_agent.service
systemctl is-active --quiet keylime_agent.service
echo "hardware TPM and measured-boot log enabled; run the quorum bootstrap next"
