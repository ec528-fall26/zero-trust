# Design Document

*Demo 2 version (10/21). Updated for `demo-3` and `final-demo`.*

This document describes what we actually built for Demo 2, how to run it, what
it shows, and what it does not show. Section 5 lists where Demo 2 differs from
the milestones in our design proposal.

## 1. Architecture

An AI agent never gets to run a workload directly. It can only ask. A request
runs only if all of these hold:

1. the agent is confined by **nono** and can only write a request file;
2. a trusted watcher turns that file into an exact, hashed action;
3. **two of three** approvers sign an **EMILIA** receipt bound to that exact
   action;
4. a receipt-checking MCP dispatcher verifies the receipt and reserves it so it
   can be used only once;
5. the execution node's **Keylime** attestation is fresh, passing, and belongs to
   the expected agent;
6. the workload and input bytes match the approved digests and are executed
   from the already-verified file descriptors.

If any step fails, is unavailable, or is ambiguous, the request is denied.

```mermaid
flowchart LR
    subgraph L["Controller laptop (trusted)"]
        subgraph S["nono sandbox (untrusted agent)"]
            A["Agent"]
        end
        O["outbox/ (agent: write-only)"]
        I["inbox/ (agent: read-only)"]
        W["Outbox watcher<br/>validates, hashes, assigns IDs"]
        E["EMILIA 2-of-3 receipt<br/>(3 demo signer keys)"]
        D["Receipt-required MCP dispatcher<br/>verify, reserve once, commit"]
        R[("Durable receipt store")]
    end
    subgraph C["AWS EC2 t3.small, AlmaLinux 10 (no inbound ports)"]
        M["Keylime MCP server<br/>127.0.0.1:3000"]
        H["Root status helper<br/>(systemd socket)"]
        K["Keylime verifier, registrar,<br/>agent + swtpm"]
        X["checksum workload<br/>(run by verified fd)"]
    end
    A --> O --> W --> E --> D
    D <--> R
    D -- "SSM port-forward tunnel" --> M
    M --> H --> K
    M --> X
    W --> I
```

### Components

| Component | Code | Role |
| --- | --- | --- |
| Agent request tool | `src/agent_tool/submit_request.py` | Writes one schema-valid request to the outbox (`*.tmp`, then rename). Convenience only, not a security boundary. |
| nono profile | `src/agent_tool/nono_profile.py` | Generates the sandbox profile: outbox write-only, inbox read-only, no network, credential variables stripped. |
| Request schema | `src/request_schema.json` | Strict JSON Schema (`additionalProperties: false`), allowlisted operations. |
| Outbox watcher | `src/controller/outbox_watcher.py` | Trusted. Opens files with `O_NOFOLLOW` and `O_NONBLOCK` and accepts only regular files. Enforces size limits, computes digests, checks the target allowlist, and assigns the occurrence ID and policy version. |
| EMILIA adapter and demo signers | `src/controller/emilia_adapter.py`, `src/demo/demo_controller.mjs` | Builds the action that approvers sign and issues 2-of-3 quorum receipts with three locally generated demo keys. |
| Receipt-required dispatcher | `src/controller/receipt_required_mcp.mjs` | Uses `@emilia-protocol/require-receipt` 0.9.0. Refuses with HTTP 428 unless a pinned issuer's receipt matches the exact action hash. Reserves the receipt in a durable store before the effect and burns it if the outcome is uncertain. |
| Keylime MCP client | `src/controller/keylime_mcp_client.mjs` | Calls the cloud MCP with a bearer token over HTTPS or a tunnelled loopback. Rejects stale, future-dated, or mismatched attestation results. |
| Keylime MCP server | `src/keylime_mcp/server.mjs`, `attest_and_deploy.mjs` | Runs on the node. Requires a fresh `PASS` for the configured agent UUID, checks workload and input digests, then runs the workload from file descriptors 3 and 4. |
| AWS deployment | `infra/aws/` | CloudFormation template, deploy, tunnel, and teardown scripts. Access is through Systems Manager only. |

## 2. Design decisions

| Decision | What we chose | Alternatives and why not |
| --- | --- | --- |
| How intent leaves the sandbox | A structured JSON file in a write-only outbox | nono's built-in approval webhook was considered. The file handoff keeps the agent fully networkless and lets the trusted side compute every security-relevant field. |
| What the agent may request | An allowlisted `operation` plus digests, never shell strings | Free-form commands make "approve this exact action" meaningless. |
| Where security fields come from | The watcher computes digests, occurrence ID, and policy version itself | Fields the agent supplies are only claims. A request whose digest does not match is rejected. |
| Receipt format | EMILIA `require-receipt` gate with a v0.1 Action Risk manifest | We use EMILIA's gate rather than our own crypto. The v0.2 Action Control manifest is newer; migrating to it is follow-up work. |
| One-use receipts | Atomic `mkdir` reservation, then commit, with fsync | An in-memory set loses replay protection on restart. The scenario `replay_after_restart` shows it survives restarts. |
| Uncertain outcomes | Burn the receipt (`effect_indeterminate`) | Retrying could run the workload twice. The cost: a Keylime outage during a request uses up that approval, and a new approval is needed. |
| Running the approved bytes | Hash through an open fd, then execute `/proc/self/fd/3` on `/proc/self/fd/4` | Re-opening the path after hashing allows a swap between check and use. |
| Root-only Keylime status | A root systemd socket-activated helper, readable only by the `ec528-mcp` group | `sudo` is blocked by the service's `NoNewPrivileges=true`, and we did not want to remove that hardening. |
| Cloud | AWS EC2 (AlmaLinux 10, `t3.small`) | See Section 5 for why not MOC. Ubuntu has no Keylime package, while AlmaLinux 10 ships Keylime 7.14.1 and the Rust agent. |
| TPM | swtpm (software TPM) | NitroTPM needs a custom UEFI AMI and IMA setup; it is planned for Demo 3. swtpm proves the Keylime protocol flow but not a hardware root of trust. |
| SELinux | Kept enforcing; added a narrow `ec528_swtpm` policy module | Disabling SELinux would have been faster but weakens the whole host. |
| Language | Python for the agent side and watcher; Node.js for EMILIA and MCP | The proposal said Python throughout. EMILIA's receipt gate and the MCP SDK are JavaScript, and we use them directly rather than port the crypto. |

**Things that did not work at first, all fixed before the recorded runs:**

- **The watcher could be frozen.** The agent could create a FIFO in the outbox, and opening it blocked the watcher. Fixed with `O_NONBLOCK`, with a regression test.
- **The workload never received its files.** `execFile` in Node silently ignores the `stdio` option, so the verified file descriptors never reached the child. Fixed by switching to `spawn`, and tested on Linux.
- **Timeouts left processes running.** A timeout did not kill grandchildren of the workload. Fixed by killing the whole process group.
- **The status check could never run.** `sudo` inside a `NoNewPrivileges` service always failed. Fixed with the socket helper.
- **SELinux stopped swtpm from starting** under our systemd unit. Fixed with a policy module rather than disabling SELinux.

## 3. Setup

### Local machine (all non-cloud experiments)

Tested on macOS 26 (Darwin 25.1), Apple Silicon. Linux-only code paths were
also tested in a `node:22-bookworm-slim` container.

| Dependency | Version used |
| --- | --- |
| Node.js | 24.11.0 (`>=20` required) |
| Python | 3.11 or newer (CI uses 3.11) |
| nono | 0.79.0 |
| `jsonschema` (Python) | 4.25.1 |
| npm packages | pinned in `package-lock.json` (`@emilia-protocol/require-receipt` 0.9.0, MCP SDK 2.x) |

```bash
git clone https://github.com/ec528-fall26/zero-trust.git
cd zero-trust
git checkout demo-2
npm ci
python3 -m venv .venv
.venv/bin/pip install -e .
# install nono 0.79.0: https://nono.sh/
nono --version
```

The commands below use `.venv/bin/python`, because the system `python3` usually
does not have `jsonschema`.

**Where to put the checkout.** Clone it under your home folder (for example
`~/ec528-demo`), not under `/tmp`, `/var`, or an iCloud-synced folder:

- nono's built-in macOS rules let any sandboxed program read `/private/var`
  (which holds the per-user temp folder) and read and write `/private/tmp`.
  A checkout there makes the confinement check fail, and the end-to-end
  experiment refuses to run (see Section 5).
- In iCloud Drive (`~/Documents`, `~/Desktop`), loading the Node packages took
  about 60 seconds instead of 0.1 seconds and stalled experiments.

### Cloud node (attestation and end-to-end experiments only)

These experiments need an AWS account. On our account the instance cost a few
cents per run.

| Dependency | Version used |
| --- | --- |
| AWS CLI | v2, plus the Session Manager plugin |
| Region / AMI | `us-east-2`, `ami-0281f4b4279b17b5b` (official AlmaLinux OS 10 x86_64) |
| Instance | `t3.small`, 16 GB encrypted gp3, auto-terminates after 4 hours |
| Keylime | 7.14.1-5.el10_2.1 (verifier, registrar, tenant; Rust agent) |
| swtpm | 0.9.0-6.el10_2 (live run; development only) |
| `cfn-lint` | run through `uvx cfn-lint` |

The deploy script expects an authenticated AWS CLI profile named
`ec528-deployer` that can create CloudFormation, EC2 and SSM resources. Create
or select the account credentials first; never commit access keys:

```bash
aws configure sso --profile ec528-deployer
aws sso login --profile ec528-deployer
aws sts get-caller-identity --profile ec528-deployer
```

The EC2 node also needs an IAM instance profile so it can register with Systems
Manager. The default is `EC528ZeroTrustInstanceProfile`. Validate it without
changing AWS, or create its least-privilege SSM role explicitly:

```bash
AWS_PROFILE=<iam-administrator-profile> ./infra/aws/setup-prerequisites.sh
AWS_PROFILE=<iam-administrator-profile> ./infra/aws/setup-prerequisites.sh --apply
```

The caller needs IAM permission to create the role/profile and attach the AWS
managed `AmazonSSMManagedInstanceCore` policy. Override the name with the
`InstanceProfileName` CloudFormation parameter if the course account already
provides an equivalent profile. A restricted deployer without
`iam:GetInstanceProfile` cannot validate whether the profile exists; the script
reports that authorization boundary instead of incorrectly reporting it as
missing.

```bash
./infra/aws/deploy.sh                 # validation only: lints the template, no charges
./infra/aws/deploy.sh --apply         # creates the instance (billable)
./infra/aws/open-tunnel.sh            # keep running: forwards localhost:3000 to the node
make demo2-bootstrap                  # 2-of-3 receipt enrolls the staged Keylime tenant
./infra/aws/teardown.sh ec528-zero-trust-demo   # deletes everything when finished
```

The experiments read the MCP bearer token from `build/aws-keylime/mcp-token`
(mode `0600`, ignored by Git). `make fetch-token STACK=<stack>` copies it from
the instance through Systems Manager. The token's value is therefore kept in
the account's SSM command history; it is per instance and useless once the
stack is torn down, but never display that command's output.

## 4. Running the experiments

Run every command from the repository root. Each experiment writes a JSON file
under `results/` containing the commit hash, whether the working tree had
uncommitted changes (`repository_dirty`), versions, per-scenario
expected/observed/pass, and its limitations. Raw responses are stored only as
SHA-256 digests, so no tokens or keys end up in Git.

### Experiment 0: unit and regression tests

| | |
| --- | --- |
| Supports | "The checks fail closed." Covers receipt binding, replay, malformed input, FIFO and symlink handling, and stale or mismatched Keylime results. |
| Command | `make ci PYTHON=.venv/bin/python` |
| Expected runtime | about 2 minutes |
| Expected output | Python `Ran 25 tests ... OK`; Node `pass 59`, `fail 0`, `skipped 1` on macOS (the Linux-only fd test), or all 60 tests passing on Linux |

### Experiment 1: nono confinement

| | |
| --- | --- |
| Supports | "The agent can only write a request. It cannot read back, reach the network, call the MCP directly, or read controller secrets." |
| Command | `make integration-nono PYTHON=.venv/bin/python NONO_BINARY=$(command -v nono)` |
| Expected runtime | under 1 minute |
| Expected output | JSON with all 9 cases `"passed": true` |

The 9 cases: `outbox_write_allowed`, `outbox_read_blocked`, `inbox_read_allowed`,
`inbox_write_blocked`, `network_blocked`, `direct_mcp_bypass_blocked`,
`receipt_store_read_blocked`, `signer_key_read_blocked`, `mcp_token_read_blocked`.

### Experiment 2: 2-of-3 exact-action authorization

| | |
| --- | --- |
| Supports | "No receipt, one signature, duplicate or untrusted signers, a changed action, expiry, and replay are all refused. Two distinct signers allow exactly one execution." |
| Command | `make demo2-authorization` (writes `results/demo2-authorization.json`) |
| Expected runtime | under 30 seconds |
| Expected output | `"status": "pass"` and 11 scenarios passing (see Section 5) |

### Experiment 3: cloud Keylime attestation (needs the AWS node and tunnel)

| | |
| --- | --- |
| Supports | "A fresh Keylime PASS lets the exact workload run. The wrong target is refused. Keylime being unavailable fails closed." |
| Command | `./infra/aws/prepare-demo.sh`, then `KEYLIME_MCP_URL=http://127.0.0.1:3000/mcp KEYLIME_MCP_TOKEN_FILE=build/aws-keylime/mcp-token KEYLIME_ACTION_FILE=build/aws-keylime/action.json KEYLIME_TPM_TYPE=swtpm make demo2-attestation` |
| Expected runtime | about 1 minute, after deploying the node (allow roughly 15 minutes) |
| Expected output | `results/demo2-attestation.json` with `"status": "pass"` and 3 scenarios passing |

### Experiment 4: one continuous end-to-end run (needs the AWS node)

| | |
| --- | --- |
| Supports | The headline claim: nono → watcher → EMILIA 2-of-3 → receipt dispatcher → SSM tunnel → cloud Keylime → workload → read-only inbox status, all in one run. |
| Command | `PYTHON_BIN=.venv/bin/python node experiments/demo2_end_to_end.mjs` (opens its own SSM tunnel; also reads `AWS_PROFILE`, `AWS_REGION`, `AWS_STACK_NAME`, `KEYLIME_MCP_TOKEN_FILE`) |
| Expected runtime | about 2 minutes. It deliberately stops the Keylime agent and waits for attestation to go stale. |
| Expected output | `results/demo2-end-to-end.json` with `"status": "pass"`, 7 scenarios passing, and a timeline from `nono_profile_generated` to `readonly_inbox_status_observed` |

### Experiment 5: policy digest pinning (local, no cloud)

| | |
| --- | --- |
| Supports | "`policy_version` is derived from the Keylime policy and the approval policy. Changing the Keylime allowlist, the approver roster, the quorum threshold or window, or the issuer key makes the gate or the node refuse an action approved under the old policies." |
| Command | `make drift-policy` (writes `results/drift-policy.json`) |
| Expected runtime | under 5 seconds |
| Expected output | `"status": "pass"` and 9 scenarios passing (listed in `results/drift-policy.json`) |

### Experiment 6: time drift (local, no cloud)

| | |
| --- | --- |
| Supports | "A receipt older than its lifetime (120 s by default) is refused. The node reports the attestation age it measured on its own clock. The controller refuses an age its timestamps do not support, and a node clock more than 5 seconds outside the interval the controller waited for the reply." |
| Command | `make drift-time` (writes `results/drift-time.json`) |
| Expected runtime | under 5 seconds |
| Expected output | `"status": "pass"` and 9 scenarios passing |

### Experiment 7: revocation at verify time (local, no cloud)

| | |
| --- | --- |
| Supports | "A receipt that verifies offline is refused if one of its signers has been revoked since, and the check fails closed when the revocation list is missing, stale, forged or rolled back." |
| Command | `make drift-revocation` (writes `results/drift-revocation.json`) |
| Expected runtime | under 5 seconds |
| Expected output | `"status": "pass"` and 9 scenarios passing |

`make drift` runs Experiments 5 to 7 together.

## 5. Claims and limitations

### Results recorded for Demo 2

Each result file records its exact source commit, dependency versions,
timestamps, and whether the working tree was dirty. The refreshed continuous
and IMA runs were generated from commit `7826c10` on 2026-10-20/21 with
`repository_dirty: false`. The instance IDs below are historical evidence; the
CloudFormation stack and all tagged EC2, EBS, and security-group resources were
deleted after the runs.

**Authorization** (`results/demo2-authorization.json`, 11/11):

| Scenario | Observed |
| --- | --- |
| `missing_receipt` | refused |
| `one_signer_pending` | pending, no receipt issued |
| `duplicate_signer` | not counted twice |
| `untrusted_signer` | refused |
| `two_distinct_signers` | receipt issued |
| `receipt_target_binding` | refused (`action_hash_mismatch`) |
| `exact_action` | executed once |
| `immediate_replay` | refused (`replay_refused`) |
| `replay_after_restart` | still refused after restart |
| `expired_evidence` | refused (`receipt_expired`) |
| `one_signer_expiry` | expired without execution |

**Continuous end-to-end run on AWS** (`results/demo2-end-to-end.json`, 7/7,
instance `i-00cf93b48c76bef44`, terminated):

| Scenario | Expected | Observed |
| --- | --- | --- |
| `no_receipt` | denied | HTTP 428 |
| `one_of_three_signatures` | pending and denied | HTTP 428, receipt not issued |
| `action_changed_after_approval` | denied | HTTP 428, `action_hash_mismatch` |
| `exact_action_end_to_end` | executed once | HTTP 200, Keylime verdict `trusted`, workload ran |
| `used_receipt_replay` | denied | HTTP 428, `replay_refused` |
| `keylime_agent_stopped` | denied | HTTP 500, `effect_indeterminate`, workload did not run |
| `keylime_agent_recovered` | executed once | HTTP 200 after re-enrollment and fresh attestation |

**Cloud attestation** (`results/demo2-attestation.json`, 3/3): fresh attestation
allows the exact workload; the wrong target is denied; Keylime unavailable fails
closed.

**IMA runtime-integrity run** (`results/ima-tamper.json`, 5/5, same terminated
instance):

| Scenario | Observed |
| --- | --- |
| `ima_active_before_tamper` | kernel IMA policy active; Keylime status `PASS` |
| `clean_node_allows_exact_workload` | HTTP 200; exact workload executed |
| `unapproved_program_measured` | unexpected executable recorded in the IMA log |
| `verifier_detects_unapproved_program` | Keylime changed to `FAIL` with `ima.validation.ima-ng.not_in_allowlist` in at most 2.2 seconds |
| `approved_request_denied_after_tamper` | HTTP 500 fail-closed response; workload did not execute |

### What these results do not show

- **swtpm is not a hardware root of trust.** It proves the Keylime protocol and
  our fail-closed handling, not that a physical chip vouched for the machine.
- **The checker and the checked machine are the same.** The Keylime verifier,
  registrar, agent, swtpm, and MCP all run on the one instance being attested.
  A compromised instance could lie about itself.
- **The three EMILIA signer keys are on one laptop.** This proves the 2-of-3
  protocol, not independent human approval.
- **IMA is real kernel measurement, but the TPM is emulated.** Linux IMA
  records executed files, then a userspace emulator copies PCR 10 into swtpm.
  Root on the node could forge this flow. The policy was generated from the
  node at boot (trust on first use), and tmpfs and the SSM per-command script
  directory are outside the measured set.
- **There is a freshness window.** We accept attestation up to 30 seconds old.
  A node that fails inside that window is still trusted until the result goes
  stale. The outage scenario waits 35 seconds for this reason.
- **An outage uses up the approval.** When Keylime is down, the receipt is
  burned as `effect_indeterminate` rather than retried, so the approvers must
  sign again.
- **What the end-to-end "one of three" scenario actually tests.** With one
  signature, no receipt exists yet, so the dispatcher sees the same "no receipt"
  case as `no_receipt`. A forged receipt carrying only one valid signature is
  refused by the gate in the unit test
  `the production profile accepts a real 2-of-3 quorum receipt`, but not in the
  live cloud run.
- **The controller trusts the node's report.** The cloud MCP returns the
  attestation verdict and evidence digest itself, so the controller cannot
  independently check them.
- **A prior temp-folder layout exposed read access to controller state.** It was
  fixed by moving experiment state under `build/runs/`. Before starting, the
  current end-to-end experiment asks `nono why --json` to confirm that every
  controller-only path is denied and fails closed otherwise. The refreshed
  result records `controller_state_unreadable_by_sandbox` with seven paths
  checked.
- **nono enforcement was tested on macOS (Seatbelt) only.** The agent ran on the
  laptop; Linux Landlock confinement of the agent was not part of these runs.
- **Small scale.** Each scenario ran once. The 20-trial and 50-run measurements
  in the proposal are not done yet.

### Changes from the Demo 2 milestones in the proposal

We are announcing these changes, as the course rules require:

| Proposal milestone | Status | Change and reason |
| --- | --- | --- |
| Exact-action 2-of-3 authorization (`demo2_authorization.sh`) | **Met** | As planned, plus target-binding and restart-replay cases. |
| Keylime enrollment with measured-boot and IMA runtime policy | **Implemented, hardware run pending** | Enrollment always attaches the generated IMA policy. On a NitroTPM/UEFI AMI, run `infra/aws/enable-hardware-tpm.sh` before bootstrap; it fails unless a hardware TPM and non-empty kernel boot event log exist, moves the agent off swtpm, and enables generation of the Keylime measured-boot reference policy. The existing swtpm evidence still proves IMA only; a NitroTPM run is required before claiming hardware-rooted measured boot. |
| Quorum-controlled tenant bootstrap through Keylime secure payload | **Implemented, cloud rerun pending** | CloudFormation now stages the runtime policy and protected payload but leaves the tenant unenrolled. `demo2_bootstrap` requires a receipt bound to the agent, policy digest, payload digest and occurrence before the node-local root helper invokes `keylime_tenant --include`. Missing, one-signer, changed and replayed approvals fail before enrollment. |
| Platform: MOC, or local KVM for this milestone | **Changed** | AWS EC2 with swtpm was used because the team had AWS credits and Systems Manager access while the MOC integration was not ready. The platform substitution is disclosed here rather than treated as equivalent hardware attestation. |
| Nono-confined agent request (planned for Demo 3) | **Started early** | Already part of the Demo 2 end-to-end run. Two real people approving from separate credentials is still Demo 3 work. |

## 6. Drift controls

*Added after Demo 2, in response to the design analysis "State Drift Between Keylime and EMILIA Quorum". That analysis is a design study, not a description of an existing integration. These controls have been run locally (Experiments 5 to 7) but not on the AWS node.*

Keylime vouches for the machine, EMILIA vouches for the humans, and the action runs later. Each check can be true at its own moment and false by the time the action runs. These controls narrow the gaps.

| Control | What it does | Where | Setting |
| --- | --- | --- | --- |
| Policy digest pinning | `policy_version` becomes `pd1-` plus the first 60 hex characters of a SHA-256 over canonical JSON of the Keylime policy file digest and the approval policy (issuer keys, approver keys, quorum policies, relying party, origins). Any change gives a new version. The gate refuses another version with `policy_version_mismatch`. | `src/keylime_mcp/policy_digest.mjs`, `src/controller/policy_digest.py`, gate option `keylimePolicySha256`, watcher flags `--keylime-policy` and `--approval-policy`, node variables `KEYLIME_POLICY_FILE` and `KEYLIME_APPROVAL_POLICY_FILE` | Optional. The fixed label (`--policy-version`, `KEYLIME_POLICY_VERSION`) still works. |
| Short receipt lifetime | A receipt is refused once older than `max_age_sec`. The window in which the two approvers must sign is separate and longer (900 s). | `public/.well-known/agent-actions.json`, `DEFAULT_RECEIPT_MAX_AGE_SEC` in `src/controller/emilia_adapter.py`, `manifestWithReceiptMaxAge` in `receipt_required_mcp.mjs` | 120 s (was 900 s). A test checks the manifest and the adapter agree. |
| Node-reported attestation age and bounded skew | The node returns `age_seconds` and `node_time` from its own clock. The controller checks the age is consistent with the node's two timestamps and at most 30 s, and that `node_time` lies within 5 s of the interval in which the controller was waiting. | `src/keylime_mcp/attest_and_deploy.mjs`, `src/controller/keylime_mcp_client.mjs` | 30 s age, 5 s skew |
| Revocation at verify time | The gate loads a signed revocation list before reserving a receipt. A receipt is refused if any signer is listed, or if the list is missing, unverifiable, older than 300 s, or older in sequence than one already seen. A refusal here does not burn the receipt. | `src/controller/revocation.mjs`, gate option `revocation` | Optional. Off unless a checker is passed. |
| Post-request attestation | With `KEYLIME_REQUIRE_FRESH_ATTESTATION=1` the node reads the verifier's `attestation_count`, waits until it has risen by 2, then runs the workload. The first increase may be a quote already in flight when the request arrived; the second was requested by the verifier, with its own nonce, after the request. The controller refuses a result that lacks `fresh_after_request`. It fails closed on timeout (default 15 s), a status that stops passing, or a count that is missing or goes backwards. | `src/keylime_mcp/attest_and_deploy.mjs`, `src/controller/keylime_mcp_client.mjs`, `src/keylime_mcp/server.mjs` | Optional, off by default. Not yet run against a real Keylime node. |

**What these controls do not do**

- **Not deployed to AWS.** `infra/aws/install-mcp.sh` still sets the fixed label `KEYLIME_POLICY_VERSION=demo-2.1`, so the recorded cloud runs do not use policy pinning, and no revocation checker is configured. The node's Keylime policy is generated at boot, so the controller does not know its digest in advance. Deciding how it learns it is open work.
- **No caller-chosen nonce.** Post-request attestation (above) shows that the verifier quoted the node again after the request, but the controller does not choose the nonce and cannot verify the quote itself. Without the option the node still reads Keylime's last periodic result, so the 30 second window in Section 5 remains. The option has unit tests only and is off in the AWS deploy.
- **A node-side refusal still burns the approval.** The refusal happens after the receipt is reserved (`effect_indeterminate`). Experiment 5 shows this for a node whose Keylime policy changed.
- **The controller trusts the node's report of its own age and clock.** A compromised node can lie about both. The consistency and skew checks catch misconfiguration and drift, not a malicious node.
- **Receipt age uses the controller's clock.** A skewed controller clock is not detected.
- **Revocation list limits.** The list authority is a local demo key and the list is served from memory. The highest sequence seen is kept in memory only, so a controller restart forgets it. A signer is refused whether the key was revoked before or after signing.
- **Receipt lifetime and live demos.** With a 120 s lifetime, a narrator has two minutes between the second approval and the execute step. For a slower walkthrough use `manifestWithReceiptMaxAge(manifest, 900)`.
