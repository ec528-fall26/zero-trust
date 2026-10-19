# Demo 2 presentation script (5 minutes)

About 700 spoken words. Times are cumulative. "Show" lines are what is on
screen. Split the speaker parts however the team likes.

---

## 0:00–0:40 — The problem (slide: one sentence and the pipeline diagram)

**Say:**
AI agents are getting access to real infrastructure. The danger isn't only that
an agent is malicious. A confused or prompt-injected agent can misuse
permissions it legitimately has. Our question: can an agent *ask* for a
workload to run, without ever being able to *run* it on its own?

Our answer has three locks, and a request runs only if all three open:
**nono** confines the agent, **EMILIA** requires two of three humans to sign
the exact action, and **Keylime** checks that the machine running it is in a
known-good state. If any lock is missing, broken, or unsure, the answer is no.

**Show:** the architecture diagram from `docs/design-document.md`, Section 1.

---

## 0:40–1:30 — Lock 1: the sandbox (slide: nono confinement results)

**Say:**
The agent runs inside nono. It has exactly one way out: it can write a request
file into an outbox. It can't read that outbox back, can't use the network,
can't call our execution server directly, and can't read the signing keys,
the receipt database, or the server's password. We test all nine of those
paths, and all nine behave as expected.

A trusted watcher outside the sandbox picks up the request. It never trusts the
agent's numbers: it computes the file hashes, the request ID, and the policy
version itself.

**Show:** `make integration-nono` output, 9/9 `passed: true`.

---

## 1:30–2:40 — Lock 2: two-of-three approval (slide: authorization table)

**Say:**
Next, two of three approvers must sign a receipt for *this exact action*: this
workload, this input, this target machine. The receipt is checked by EMILIA's
own receipt gate, not by crypto we wrote ourselves.

We tested eleven cases. With one signature, it stays pending. The same person
signing twice counts once. A signer we don't trust is refused. If the action
changes even slightly after approval, say a different target or a different
input file, the hash no longer matches and it's refused. A receipt works once:
replaying it is refused, even after we restart the server. And receipts
expire.

**Show:** the 11-row authorization table from `results/demo2-authorization.json`.

---

## 2:40–3:50 — Lock 3 and the full run in the cloud (slide: end-to-end table)

**Say:**
The third lock is attestation. We deployed a real Keylime setup on an AWS
machine with no open inbound ports; we reach it only through AWS Systems
Manager. Before the workload runs, the server asks Keylime: is this exact
machine's attestation passing and less than 30 seconds old? Then it checks that
the workload file is byte-for-byte the approved one, and runs that verified
copy, so nothing can be swapped in between.

Then we ran everything together in one continuous run: agent in nono, watcher,
two signatures, receipt check, tunnel to AWS, Keylime, workload. The exact
approved action ran once. No receipt, one signature, a changed action, and a
replay were all denied. Then we stopped the Keylime agent, and the same kind of
approved request was denied. We restarted it, attestation became fresh again,
and the request worked.

**Show:** the 7-row table from `results/demo2-end-to-end.json`, and its timeline
from `nono_profile_generated` to `readonly_inbox_status_observed`.

---

## 3:50–4:30 — What this does *not* prove yet (slide: honest limitations)

**Say:**
We want to be precise about what's real.

- The TPM is **software (swtpm)**, not a hardware chip. This proves the
  protocol, not hardware-rooted trust.
- The Keylime checker runs **on the same machine it checks**, so a fully
  compromised machine could lie.
- The three signing keys are **on one laptop**. This proves the 2-of-3
  protocol, not three independent people.
- The only attestation failure we tested is an **outage**. We haven't yet shown
  a tampered file being caught by IMA.
- There's a **30-second freshness window**, and a Keylime outage **uses up**
  the approval, so people must sign again. That's deliberate: we never retry
  something that might already have run.

**Show:** the "What these results do not show" list from the design document.

---

## 4:30–5:00 — Changes to our plan, and Demo 3 (slide: milestone table)

**Say:**
Compared with our proposal: the 2-of-3 authorization milestone is met. The
Keylime milestone is partly met. Real attestation works, but measured-boot and
IMA policies and the secure-payload bootstrap moved to Demo 3. We used AWS
instead of MOC *[TEAM: give the one-line reason]*. The nono-confined agent was
planned for Demo 3 and is already working.

For Demo 3: NitroTPM with a real IMA tamper test, a verifier that runs off the
node it checks, two real people approving from separate machines, and the
repeated trials and timing from our proposal.

Every number we showed today comes from a script in `experiments/` and a
result file in `results/`, recorded at commit `7de165c`.

**Show:** the milestone-changes table from the design document.

---

### Backup answers for likely questions

- **"Why not just use IAM / RBAC?"** We still do. IAM decides who may call
  an API. It doesn't bind a specific human-approved action to a verified
  machine, and a prompt-injected agent can misuse permissions it already has.
- **"Why files instead of nono's approval webhook?"** It keeps the agent fully
  offline, and the trusted side computes every security field.
- **"What if the approval succeeds but the machine dies mid-run?"** The receipt
  is marked used (`effect_indeterminate`) and never automatically retried.
  Running something twice is worse than running it zero times.
- **"Can we see it live?"** The AWS stack is torn down to avoid cost.
  Redeploying takes roughly 15 minutes (`./infra/aws/deploy.sh --apply`). The
  local parts (`make integration-nono`, `make demo2-authorization`) run in
  under a minute.
