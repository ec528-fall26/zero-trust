# Demo 2 presentation script (5 minutes)

Nine slides, about 720 spoken words. Times are cumulative. **On screen** is
what the slide shows; **Say** is the speaker text. Split the speaking parts
however the team likes.

---

## Slide 1 — The problem (0:00–0:30)

**On screen:** Title, and one line: "Can an AI agent *ask* to run a workload
without being able to *run* it?"

**Say:**
AI agents are getting real access to infrastructure. The risk isn't only a
malicious agent. A confused or prompt-injected agent can misuse permissions it
legitimately has. So we asked: can an agent ask for a job to run without ever
being able to run it by itself?

---

## Slide 2 — Three locks (0:30–1:00)

**On screen:** The architecture diagram from `docs/design-document.md`:
agent → watcher → EMILIA → dispatcher → AWS node.

**Say:**
A request has to get through three locks. Nono confines the agent. EMILIA
requires two of three people to sign the exact action. Keylime checks that the
machine that runs it is in a known-good state. If any lock fails, is
unavailable, or isn't sure, the answer is no.

---

## Slide 3 — Lock 1: the sandbox (1:00–1:30)

**On screen:** The 9 confinement checks, all passing (`make integration-nono`).

**Say:**
The agent runs inside nono. Its only way out is writing a request file into an
outbox. It can't read that back, can't use the network, can't call our cloud
server directly, and can't read the signing keys, the receipt database, or
the server password. We test all nine of those paths. A trusted watcher
outside the sandbox then rebuilds the request itself: it computes the file
hashes and IDs and never trusts the agent's numbers.

---

## Slide 4 — Lock 2: two-of-three approval (1:30–2:10)

**On screen:** The 11-row authorization table (`results/demo2-authorization.json`).

**Say:**
Two of three approvers must sign a receipt for *this exact action*: this
workload, this input, this machine. We use EMILIA's own receipt checker rather
than writing our own crypto. One signature stays pending. The same person
signing twice counts once. An untrusted signer is refused. Change anything
after approval, even the target, and the hash no longer matches. Receipts
expire, and each works once: replaying one is refused, even after a restart.

---

## Slide 5 — Where it runs (2:10–2:40)

**On screen:** The AWS diagram (laptop → Systems Manager → EC2 node; "what
anyone can review" row). Optional small inset: one cropped CloudTrail row.

**Say:**
The protected machine is an AWS server we create from a script and delete after
each run. It has no open ports and no SSH. The only way in is AWS Systems
Manager, so every command is authenticated and logged. Afterwards three
records exist: AWS's own audit log, a trace of every step, and our results
files. None of them contain passwords or keys.

---

## Slide 6 — The whole chain, live (2:40–3:25)

**On screen:** Jaeger trace of the live end-to-end run (17 spans, 2 min 36 s;
`results/traces/otel-demo2-end-to-end.trace.json`).

**Say:**
Here's one continuous run, traced live. Each bar is a step. The agent writes
its request in the sandbox, the watcher builds the trusted action, we tunnel
to AWS. Missing receipt, one signature, a changed action: each refused in
milliseconds. With two signatures, the approved job runs, and nested inside it
is the Keylime check on the cloud machine. A replay is refused. Then we stop
Keylime on purpose: the next approved request fails. That red mark is the
system refusing, not breaking. We restart it, and requests work again.

---

## Slide 7 — Catching a tampered machine (3:25–4:05)

**On screen:** Jaeger trace of the IMA tamper run (12 spans, 15 s), with the
`keylime.wait_for_detection` bar highlighted; caption "detected in ~2 s".

**Say:**
Keylime isn't only checking that the machine is up. With IMA, Linux
fingerprints every program the machine runs, and Keylime compares those
fingerprints to an approved list. Here, the clean machine runs the approved
job. Then we run a program that isn't on the list. Keylime flags the machine
within about two seconds and names the exact file. The next request, even
with two valid signatures, is denied.

---

## Slide 8 — What this does *not* prove yet (4:05–4:35)

**On screen:** Four bullets.

**Say:**
We want to be precise about what's real. The TPM is software, so IMA's
fingerprints are copied into it by a helper, which someone with full control of
the machine could fake. Keylime runs on the same machine it checks. The three
signing keys are on one laptop. And there's a 30-second freshness window; a
Keylime outage also uses up the approval, on purpose, because we never retry
something that might already have run.

---

## Slide 9 — Plan changes and Demo 3 (4:35–5:00)

**On screen:** Milestone table: authorization **met**; Keylime with IMA tamper
detection **met on a software TPM**; measured boot and secure-payload bootstrap
**moved to Demo 3**; AWS instead of MOC.

**Say:**
Against our proposal: authorization is done, and Keylime with tamper detection
works on a software TPM. Measured boot and the secure-payload setup step move
to Demo 3. We used AWS because the team had credits and Systems Manager access
while the MOC integration was not ready. Next: a real NitroTPM chip, the
checker on its own machine, two real people approving from separate devices,
and repeated, timed trials. Every number today comes from a script in
`experiments/` and a results file in `results/`.

---

### Backup answers for likely questions

- **"Why not just IAM or RBAC?"** We still use them. IAM decides who may call an
  API. It doesn't tie a specific human-approved action to a verified machine,
  and a prompt-injected agent can misuse permissions it already has.
- **"Why is there a red error in the trace?"** It marks a refused request. A
  refusal there is the result we want.
- **"How fast is detection?"** About 2 seconds in our runs, measured from
  running the unapproved program to Keylime reporting a failure. Each run was
  done once, so this is an observation, not a benchmark.
- **"Can we see it live?"** The AWS machine is deleted to avoid cost.
  Redeploying takes about 15 minutes; the traces can be replayed any time with
  `make jaeger` and `make trace-replay`.
- **"What if a machine dies mid-run?"** The receipt is marked used and never
  retried automatically. Running something twice is worse than zero times.
