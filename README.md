# EC528 Project — Zero Trust Cryptographic Confinement for AI Agents

**Team:** EC528 Zero Trust team

**Mentor:** Charles Munson (MIT Lincoln Laboratory)

**Demo:** [silent end-to-end recording](slides/demo-2.mp4)

## What this is

This project prevents an untrusted AI agent from directly executing a cloud
workload. **nono** confines the agent, **EMILIA** requires a receipt signed by
two distinct approvers for the exact action, and **Keylime** verifies the target
node before the receipt-gated MCP server runs digest-verified workload bytes.

The implementation fails closed: missing or altered approvals, replayed
receipts, unavailable attestation, and runtime-integrity failures all deny
execution.

## Quick start

```bash
git clone https://github.com/ithlambelle/zero-trust-cryptography.git
cd zero-trust-cryptography
git checkout demo-2

npm ci
python3 -m venv .venv
.venv/bin/pip install -e .

make ci PYTHON=.venv/bin/python
make demo PYTHON=.venv/bin/python
```

The local dashboard demonstrates receipt issuance, exact-action binding, and
replay protection without cloud credentials. The recorded results and demo
video use the AWS/Keylime path. See the design document for cloud setup,
limitations, and teardown instructions.

## Repository layout

| Path | Contents |
| --- | --- |
| `docs/` | Design proposal and design document |
| `slides/` | Demo recording and presentation support files |
| `src/` | Agent handoff, controller, receipt gate, and Keylime MCP code |
| `experiments/` | Scripts that reproduce every result you claim |
| `infra/aws/` | CloudFormation deployment, SSM tunnel, and teardown scripts |
| `results/` | Sanitized, versioned evidence from reproducible runs |
| `public/` | Browser demo UI |

## Reproducing our results

See [`docs/design-document.md`](docs/design-document.md). Every security claim
has a corresponding script in `experiments/` and sanitized evidence in
`results/`. The latest live run shows:

- a nono-confined agent cannot read controller state or reach the MCP server;
- one approval remains pending, while two distinct approvals issue a receipt;
- changing the action or replaying the receipt is denied;
- a fresh Keylime `PASS` permits the exact workload;
- an unapproved executable changes Keylime to `FAIL`, after which an otherwise
  approved request is denied.

## Scope

The Demo 2 cloud node uses `swtpm`, not a hardware TPM. The verifier, agent,
software TPM, and MCP server run on one EC2 instance, and the three demo signing
keys live on one controller. These runs prove the protocol and enforcement
flow, not independent hardware attestation or independent human custody. Full
limitations are recorded in the design document and every relevant result
file.

## Submission checklist

Deliverables are collected from a **branch named for the demo**, at **12:00 noon**
on the day of that demo. See the
[submission instructions](https://ec528.github.io/ec528/fall26/setup/).

| Deliverable | Branch | Must contain |
| --- | --- | --- |
| Demo 1 | `demo-1` | slides, code, `docs/design-proposal.md` |
| Demo 2 | `demo-2` | slides, code, `docs/design-document.md`, demo video |
| Demo 3 | `demo-3` | slides, code, updated `docs/design-document.md`, demo video |
| Final | `final-demo` | slides, code, artifact documentation, recorded video presentation |
