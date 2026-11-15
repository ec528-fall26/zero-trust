# Windows Setup

*Added for `demo-3`. Tested on Windows 11 Pro with Hyper-V (2026-11-04 to
11-06) and on Windows 11 Home with VirtualBox.*

This document explains how to run our experiments from a Windows laptop. Every
project command runs inside an AlmaLinux 10 virtual machine; Windows only hosts
the VM and the terminal. The experiments themselves, their commands and their
expected outputs are in [Section 4 of the design document](design-document.md#4-running-the-experiments).
This document covers only what differs on Windows.

## 1. Why a VM, not WSL2

nono does not run natively on Windows, and it cannot run our profile under
WSL2. The profile sets `linux.af_unix_mediation = "pathname"`, which needs
seccomp user notification. WSL2 refuses it with `EBUSY`, so nono cannot start.
Every Experiment 1 case then exits with code 1, and the seven "blocked" cases
report `"passed": true` even though nothing ran. Updating the WSL kernel does
not help.

A full Linux VM runs a normal kernel and does not have this problem. We use
AlmaLinux 10 because it matches the AWS node.

| Windows edition | VM software |
| --- | --- |
| 11 Pro, Enterprise or Education | Hyper-V (built in); this document uses it |
| 11 Home | VirtualBox with the same ISO; Sections 3 to 5 are unchanged |

Check the edition with Win+R, then `winver`.

## 2. Creating the VM

You need about 40 GB of free disk, 2 to 4 GB of free RAM, and the
[AlmaLinux 10 x86_64 boot ISO](https://almalinux.org/get-almalinux/). Run
`wsl --shutdown` first if WSL is running; it holds memory as "Vmmem".

Turn on Hyper-V in an Administrator PowerShell and restart:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

In Hyper-V Manager, choose New, then Virtual Machine:

| Setting | Value |
| --- | --- |
| Name | `alma10-zero-trust` |
| Generation | 2 |
| Memory | 2048 MB startup with Dynamic Memory (1024 to 4096 MB) |
| Networking | Default Switch |
| Virtual hard disk | 40 GB |
| Installation | Bootable image file: the AlmaLinux ISO |

Before the first boot, open the VM's Settings and change three things:

- **Security.** Set the template to *Microsoft UEFI Certificate Authority*.
  Linux does not boot with the default template.
- **Processor.** 2 or more virtual processors.
- **Integration Services.** Tick *Time synchronization* (see Section 4).

Install AlmaLinux with *Minimal Install*, turn the network on, and create a user
marked as administrator. Type the host name (for example `alma-vm`) in the Host
Name box, not in the network device's Device field. If the installer reappears
after rebooting, eject the ISO (Media, DVD Drive, Eject) and reset the VM.

The Hyper-V console cannot paste, so enable SSH in the VM window and work from
Windows Terminal afterwards:

```bash
sudo systemctl enable --now sshd
ip -4 addr show eth0          # the address after "inet"
```

```powershell
ssh <vm-user>@<vm-ip>         # from a regular (not Administrator) PowerShell
```

The VM's address can change after Windows restarts; Hyper-V Manager shows the
current one on the VM's Networking tab.

## 3. Setting up the project in the VM

Install the tools that Minimal Install leaves out:

```bash
sudo dnf install -y git python3 python3-pip nodejs npm make curl gcc tar unzip jq chrony
node --version                     # 20 or newer
cat /sys/kernel/security/lsm       # must include "landlock"
```

Then follow the local setup in Section 3 of the design document (clone under
your home folder, `npm ci`, the `.venv`, nono 0.79.0). Two notes apply to the
VM:

- **nono download.** The installer at <https://nono.sh/> timed out from our VM.
  Copying a Linux x86_64 `nono` binary in with `scp` and placing it in
  `~/.local/bin` works.
- **Script permissions.** If a script reports `Permission denied`, run it as
  `bash ./path/to/script.sh` instead of using `chmod`. `deploy.sh` refuses to
  run on a modified working tree, and a mode change counts as a modification.

Before trusting an Experiment 1 result, check that it ran in the VM: the two
"allowed" cases must exit with code 0, and `uname -r` must not contain
`microsoft-standard-WSL2`.

## 4. Running the cloud experiments from the VM

The cloud setup is in Section 3 of the design document. Three things are
specific to running it from a VM.

**Keep the VM clock in sync.** The VM's clock drifts, by hours after the laptop
sleeps. AWS then rejects every call with `Signature expired`, and Keylime's
30-second freshness check fails. Make chrony correct large jumps and poll every
minute:

```bash
sudo sed -i 's/^makestep.*/makestep 1 -1/' /etc/chrony.conf
sudo sed -i -E '/^(pool|server) /{/maxpoll/!s/$/ maxpoll 6/}' /etc/chrony.conf
sudo systemctl enable chronyd && sudo systemctl restart chronyd && sudo chronyc makestep
```

and turn on Hyper-V time sync in an Administrator PowerShell:

```powershell
Enable-VMIntegrationService -VMName alma10-zero-trust -Name "Time Synchronization"
```

**Use access keys for the deployer profile.** Our course account uses IAM
users, not SSO, so create the profile with
`aws configure --profile ec528-deployer`.

**Use two terminals.** `open-tunnel.sh` occupies its terminal for the whole
run. Open two Windows Terminal tabs, SSH into the VM from both, and run the
tunnel in one and everything else in the other.

To copy results back to Windows, run this from PowerShell:

```powershell
scp -r <vm-user>@<vm-ip>:zero-trust/results C:\Users\<you>\Documents\zero-trust-results
```

## 5. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| All 9 nono cases exit 1 | Running in WSL2 (`EBUSY`) | Use the VM; check `uname -r` |
| `Unable to allocate 4096 MB of RAM (0x800705AA)` | Not enough free memory | `wsl --shutdown`; use Dynamic Memory as in Section 2 |
| Memory settings are greyed out or `Set-VMMemory` fails | VM is running, saved or paused | Shut it down; delete any saved state |
| VM does not boot | Default Secure Boot template | Security: Microsoft UEFI Certificate Authority |
| No network in the installer | Host name typed into the Device field | Use the Host Name box |
| `make: command not found` | Minimal Install | `sudo dnf install -y make curl` |
| `No module named 'jsonschema'` | System Python used | Pass `PYTHON=.venv/bin/python` |
| `nono binary was not found:` with an empty path | nono not installed in the VM | Section 3 |
| `curl: (28) Failed to connect to nono.sh` | Site unreachable from the VM | Copy the binary in with `scp` |
| `SignatureDoesNotMatch ... Signature expired` | VM clock drifted | `sudo chronyc makestep`; apply Section 4 |
| `deploy.sh` refuses to run | Modified working tree | `git status --short`, then commit or restore |
| `The config profile (ec528-deployer) could not be found` | Profile not created | `aws configure --profile ec528-deployer` |
| `ssh` times out | VM address changed | Check the VM's Networking tab in Hyper-V Manager |
