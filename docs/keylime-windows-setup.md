# Keylime Development Environment

**Author:** Kim · **Branch:** `kim/keylime-windows-env`

This guide sets up a local [Keylime](https://keylime.dev) remote-attestation environment for development. Everything runs on one machine: the Keylime **verifier**, **registrar** and **agent**, plus a **software TPM** (swtpm) that the agent uses in place of real TPM hardware.

> [!WARNING]
> **Development only.** The agent uses a software TPM, so a passing attestation proves the plumbing works, not that the machine is trustworthy. Nothing here is tied to a hardware root of trust. The final evaluation runs on MOC with hardware TPMs.

## Contents

- [Pinned versions](#pinned-versions)
- [Choose your setup script](#choose-your-setup-script)
- [AlmaLinux 10 (native or WSL terminal)](#almalinux-10-native-or-wsl-terminal)
- [Windows (WSL 2, from PowerShell)](#windows-wsl-2-from-powershell)
- [macOS (Lima VM)](#macos-lima-vm)
- [What the scripts set up](#what-the-scripts-set-up)
- [Checking that it works](#checking-that-it-works)
- [Everyday commands](#everyday-commands)
- [Troubleshooting](#troubleshooting)

## Pinned versions

The scripts were checked against AlmaLinux 10.2 AppStream on 2026-09-30:

| Package | Version |
|---|---|
| keylime | 7.14.1 |
| keylime-agent-rust | 0.2.9 |
| swtpm / swtpm-tools | 0.9.0 |
| tpm2-tools | 5.7 |

`dnf` installs whatever the repositories currently provide. The table is a record of what was tested, not a lock.

## Choose your setup script

All three scripts produce the same environment and are safe to rerun: each step skips work that is already done.

| You are on | Run this | From |
|---|---|---|
| AlmaLinux 10 (installed directly, or a WSL terminal) | `scripts/setup-keylime-dev.sh` | the AlmaLinux terminal |
| Windows with WSL 2 | `scripts/setup-keylime-dev-wsl.ps1` | a Windows PowerShell window |
| macOS | `scripts/setup-keylime-dev-vm.sh` | the macOS Terminal |

If you already have an AlmaLinux terminal open (including inside WSL), use the first one. The PowerShell script exists for driving WSL from the Windows side.

## AlmaLinux 10 (native or WSL terminal)

**Requirements:** AlmaLinux 10 with systemd running and a user that can `sudo`.

From the repository root:

```bash
sudo bash ./scripts/setup-keylime-dev.sh
```

It asks for your password once. The last line should be:

```
attestation_status: PASS
```

Running it through `bash` avoids needing execute permission on the file. To run it as `./scripts/setup-keylime-dev.sh` instead, first run `chmod +x scripts/setup-keylime-dev.sh` once.

## Windows (WSL 2, from PowerShell)

**Requirements:** Windows 10/11 with WSL 2. The script installs the `AlmaLinux-10` distro if it is missing and turns on systemd in it if needed.

From the repository root in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup-keylime-dev-wsl.ps1
```

If your distro has a different name (check with `wsl -l`), pass it in:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup-keylime-dev-wsl.ps1 -Distro AlmaLinux10
```

You can also set `$env:WSL_DISTRO` instead of passing `-Distro`.

> [!NOTE]
> WSL shuts a distro down a short while after its last terminal closes, and that stops the Keylime services with it. Keep a WSL terminal open while you work. Rerunning the script brings everything back.

## macOS (Lima VM)

**Requirements:** [Lima](https://lima-vm.io) (`brew install lima`).

From the repository root:

```bash
./scripts/setup-keylime-dev-vm.sh
```

This creates (or starts) a Lima VM named `keylime` from the `almalinux-10` template and runs the same setup inside it. To use a different VM name, run it as `VM=othername ./scripts/setup-keylime-dev-vm.sh`.

Run Keylime commands inside the VM with `limactl shell keylime`, e.g.:

```bash
limactl shell keylime sudo keylime_tenant -c reglist
```

## What the scripts set up

```
 keylime_tenant (CLI)
        │ enroll / status
        ▼
 ┌──────────────┐   polls quotes   ┌──────────────┐  TPM commands  ┌────────────────┐
 │   verifier   │ ───────────────▶ │    agent     │ ─────────────▶ │ swtpm (sw TPM) │
 │  :8881 TLS   │                  │  :9002 TLS   │                │ :2321 / :2322  │
 └──────────────┘                  └──────┬───────┘                └────────────────┘
                                          │ registers EK / AK
                                          ▼
                                   ┌──────────────┐
                                   │  registrar   │
                                   │ :8890 / :8891│
                                   └──────────────┘
```

All ports listen on `127.0.0.1` only.

| Component | systemd unit | Port(s) |
|---|---|---|
| Software TPM | `swtpm-keylime` | 2321 (TPM), 2322 (control) |
| Verifier | `keylime_verifier` | 8881 |
| Registrar | `keylime_registrar` | 8890 (HTTP), 8891 (TLS) |
| Agent | `keylime_agent` | 9002 |

Step by step, the setup script:

1. **Installs** `keylime`, `keylime-agent-rust`, `swtpm`, `swtpm-tools` and `tpm2-tools` with `dnf`.
2. **Creates the software TPM's state** once in `/var/lib/swtpm/keylime`, including endorsement key (EK) and platform certificates signed by swtpm's local test CA.
3. **Adds a `swtpm-keylime` service** that runs the software TPM as the `tss` user. If a hand-started `swtpm` is holding port 2321, the script stops it first.
4. **Points the agent at the software TPM** with a systemd drop-in, `/etc/systemd/system/keylime_agent.service.d/10-swtpm.conf`, that sets `TCTI=swtpm:host=127.0.0.1,port=2321`. Without it, the agent looks for `/dev/tpm0` and crash-loops.
5. **Trusts the software TPM's EK** by copying swtpm's local CA certificates into `/var/lib/keylime/tpm_cert_store/`.
6. **Starts the services in order:** software TPM, verifier (it creates the CA the others share), registrar, then agent. It waits for each one's port to open instead of sleeping. The agent is *restarted* so it picks up the TPM settings even if it was already crash-looping.
7. **Enrolls the agent** with the verifier, using Keylime's default agent UUID `d432fbb3-d2f1-4a97-9ef7-75bd81c00000`:
   - If the verifier has never seen it, the script adds it.
   - If it is already enrolled and working, the script leaves it alone.
   - If it is stuck in a failed state (`Failed`, `Invalid Quote`, `Tenant Quote Failed`, `Terminated`), the script deletes the stale entry and adds it again.
8. **Waits for the first attestation** (up to about 30 seconds) and prints `attestation_status`. The script exits non-zero unless it is `PASS`.

No IMA runtime policy or measured-boot policy is configured, so the verifier checks the TPM quote itself but no file or boot measurements.

## Checking that it works

On AlmaLinux or inside WSL (on macOS, prefix each command with `limactl shell keylime`):

```bash
# All four services should print "active"
systemctl is-active swtpm-keylime keylime_verifier keylime_registrar keylime_agent

# The software TPM should answer
TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321" tpm2_getcap properties-fixed | head

# The agent should be registered
sudo keylime_tenant -c reglist

# The agent should be attesting: look for "attestation_status": "PASS"
sudo keylime_tenant -c cvstatus -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000 2>&1 \
  | grep -oE '"(operational_state|attestation_status)": "[^"]*"'
```

`keylime_tenant` prints its results through its logger, which writes to stderr. Add `2>&1` before piping its output to `grep`.

## Everyday commands

```bash
# Follow a service's logs
sudo journalctl -u keylime_agent -f

# Restart everything in order
sudo systemctl restart swtpm-keylime keylime_verifier keylime_registrar keylime_agent

# Remove the agent from the verifier, then enroll it again
sudo keylime_tenant -c delete -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000
sudo keylime_tenant -c add -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000 -t 127.0.0.1 -v 127.0.0.1

# Stop everything
sudo systemctl stop keylime_agent keylime_registrar keylime_verifier swtpm-keylime
```

The registrar's unit is `keylime_registrar` (not `keylime_register`).

## Troubleshooting

### Agent crash-loops with `Failed to open specified TCTI device file /dev/tpm0`

The agent is looking for a hardware TPM. The `10-swtpm.conf` drop-in is missing, or the agent hasn't been restarted since it was added. Rerun the setup script, or check the drop-in and restart the agent:

```bash
cat /etc/systemd/system/keylime_agent.service.d/10-swtpm.conf
sudo systemctl daemon-reload && sudo systemctl restart keylime_agent
```

### `tpm2_getcap` fails with `Failed to send MS_SIM_NV_ON platform command`

The TCTI is set to `mssim`, which is for Microsoft's TPM simulator. swtpm needs the `swtpm` TCTI:

```bash
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
```

### `Connection refused` on port 2321

The software TPM isn't running. Check `systemctl status swtpm-keylime`. If you started `swtpm` by hand earlier, stop it (`sudo pkill -x swtpm`) and let the service own the port.

### `Verifier ... responded indicating a conflict ... Run "delete" or "update" first`

The agent is already enrolled with the verifier. Older versions of the setup script hit this when the agent was in a state other than `Get Quote`; the current scripts handle it. To clear it by hand, use the `delete` then `add` commands under [Everyday commands](#everyday-commands).

### `Failed to parse PEM data ... InvalidSetOrdering` warnings

These are harmless. swtpm's test certificates aren't strictly DER-encoded, so Python's `cryptography` library rejects them and Keylime falls back to another parser. The quote is still validated.

### `IMA measurement list not available` / `Measured boot measurement list not available`

These are expected here. There is no IMA policy or hardware event log in this setup, and neither is checked.

### `Permission denied` when "running" a file like `~/.bashrc` or `/etc/keylime/agent.conf`

Typing a file's path on its own tries to execute it. Use `source ~/.bashrc` to load a shell file, and `sudo less /etc/keylime/agent.conf` (or `sudoedit`) to read or edit a config file.

### PowerShell says running scripts is disabled

Run the script with `-ExecutionPolicy Bypass` as shown in [Windows](#windows-wsl-2-from-powershell). This applies only to that one run.

### Starting over

To rebuild the software TPM from scratch (this gives the agent a new identity, so re-enroll it afterwards):

```bash
sudo keylime_tenant -c delete -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000
sudo systemctl stop keylime_agent swtpm-keylime
sudo rm -rf /var/lib/swtpm/keylime /var/lib/keylime/agent_data.json
sudo bash ./scripts/setup-keylime-dev.sh
```

On macOS you can instead delete the whole VM with `limactl delete --force keylime` and rerun `setup-keylime-dev-vm.sh`.
