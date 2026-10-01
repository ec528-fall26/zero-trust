# Local development environment: Keylime attestation

**Author:** Bharath · **Date:** 2026-09-30 · **Branch:** `bharath/keylime-dev-env`

This sets up the attestation half of the Actuator Space on a MacBook: a Linux VM
running Keylime's verifier, registrar and agent, with a software TPM, and one
agent that passes attestation every 2 seconds. It is the starting point for the
Demo 2 milestone "Keylime enrollment and protected bootstrap."

> **Development only.** The node uses `swtpm`, a software TPM emulator, so
> attestation is not tied to a hardware root of trust. Keylime itself logs an
> `INSECURE` warning for this. The final evaluation runs on MOC.

## Where this fits

```
AI agent (Nono) ──request──▶ EMILIA Gate ──quorum──▶ tenant wrapper ──mTLS──▶ Keylime
                                                     (not built yet)          │
                                                                              ▼
                                              ┌─────────── Lima VM (AlmaLinux 10) ───────────┐
                                              │ keylime_verifier  :8881  checks TPM quotes    │
                                              │ keylime_registrar :8890/:8891 knows agents    │
                                              │ keylime_agent     :9002  on the attested node │
                                              │ swtpm             :2321  software TPM         │
                                              └───────────────────────────────────────────────┘
```

Everything in the box exists now. Everything to its left is still to build.

## What was built

| Piece | Version | Port (localhost) | Role |
| --- | --- | --- | --- |
| Lima VM, AlmaLinux 10.2 (aarch64) | Lima 2.2.0 | – | Linux host for Keylime on macOS |
| `keylime` (verifier, registrar, tenant) | 7.14.1 | 8881, 8890, 8891 | Checks attestation evidence, tracks agents |
| `keylime-agent-rust` | 0.2.9 | 9002 | Runs on the node, answers quote requests |
| `swtpm` + `swtpm-tools` | 0.9.0 | 2321, 2322 | Software TPM with EK certificates |
| `tpm2-tools` | 5.7 | – | Manual TPM checks |

Configuration added on top of the packages:

- `/etc/systemd/system/swtpm-keylime.service` runs the software TPM as the `tss` user and starts on boot.
- `/etc/systemd/system/keylime_agent.service.d/10-swtpm.conf` points the agent at the software TPM (`TCTI=swtpm:host=127.0.0.1,port=2321`).
- swtpm's local CA certificates are copied into `/var/lib/keylime/tpm_cert_store/` so the tenant trusts the TPM's endorsement key certificate.

## Reproduce it

On an Apple Silicon or Intel Mac with Homebrew:

```bash
brew install lima
./scripts/setup-keylime-dev-vm.sh
```

The script creates the VM if needed, installs and configures everything, and
enrolls the agent. It is safe to re-run. It should end with:

```
"attestation_status": "PASS"
```

## Check it by hand

```bash
limactl shell keylime
sudo keylime_tenant -c reglist                                          # registrar knows the agent
sudo keylime_tenant -c cvstatus -u d432fbb3-d2f1-4a97-9ef7-75bd81c00000  # expect "Get Quote" and "PASS"
sudo journalctl -u keylime_verifier -n 20 --no-pager                    # a quote every 2 seconds
```

## Decisions

| Decision | Why | Alternatives rejected |
| --- | --- | --- |
| AlmaLinux 10 VM | Keylime's installation docs list packages for RHEL 9 or later; AlmaLinux is a free RHEL-compatible rebuild with Keylime 7.14.1 in AppStream | Ubuntu (no Keylime package), Fedora (not in Keylime's documented list), building from source (slower, harder for the TA to reproduce) |
| Lima | Lightweight VMs on Apple Silicon, scriptable from the terminal | UTM (GUI-driven, harder to script) |
| swtpm inside the VM | Lima's `vz` driver does not give the VM a TPM | Waiting for MOC access before any attestation work |

## Current limits

- **No measured boot or IMA runtime policy yet.** The verifier only checks that quotes are genuine TPM quotes, so it accepts any software state. PCRs are all zero because no real boot was measured into the software TPM.
- **Default agent UUID** (`d432fbb3-…`). Fine for one node; each node needs its own for more.
- **Everything listens on 127.0.0.1**, inside one VM. The final setup splits the control plane and the node.
- **Warnings `Failed to parse PEM data`** come from swtpm's loosely encoded certificates. Keylime falls back to another parser and validation still succeeds.

## Next steps

1. Add an IMA runtime policy so Keylime allowlists specific audited scripts (the audit-then-allowlist flow from the 9/25 mentor meeting).
2. Write the tenant wrapper that receives a quorum-approved request from EMILIA Gate over mutual TLS and delivers the payload.
3. Repeat the setup on MOC once access and TPM type are confirmed.