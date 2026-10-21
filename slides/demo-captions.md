# Demo 2 recording: shots, captions and narration

Run `make demo-record STACK=<stack>` after deploying. It checks everything, then
pauses before each shot so you can start and stop recording. Each shot below
lists the **on-screen caption** to add in editing, an optional **narration**
line, and **edit notes**.

Target length: about 3–4 minutes for the full video; cut shots 2 and 4 to
60–90 seconds for the talk.

## Before you press record

- Run from a checkout outside iCloud Drive (otherwise commands stall).
- Make the terminal font large; close notifications and unrelated windows.
- Arrange: terminal on the left, browser on the right.
- Never show `build/aws-keylime/mcp-token`, or the output of the SSM command
  commented "ec528 fetch MCP token". Showing the AWS account number is fine.

---

## Title card (3 s)

**Caption:** Zero-trust confinement for AI agents — Demo 2

---

## Shot 1 — The agent is sandboxed (about 20 s)

**Caption:** The AI agent runs in a nono sandbox. Its only way out is a request file.

**Narration:** We try every other way out (reading back, the network, calling
the cloud server directly, reading keys) and each one is blocked.

**Edit notes:** Hold on the "9/9 passed" line for 2 seconds.

---

## Shot 2 — Two of three people must approve (60–90 s)

Add one caption per click, timed to the click:

| Click | Caption |
|---|---|
| Try without receipt | No approval → refused |
| Approve as operator | 1 of 3 approvals → still pending |
| Approve as security | 2 of 3 approvals → receipt issued |
| Try altered target | Request changed after approval → refused |
| Run approved workload | Approved job runs on AWS after Keylime confirms the machine is healthy |
| Replay receipt | Same receipt used twice → refused |

**Narration:** Two of three people sign this exact request. Change anything
and the signature no longer matches. Each approval works once. The approved
job only runs after Keylime vouches for the cloud machine.

**Edit notes:** Zoom in on the "Latest result" panel after "Run approved
workload" so the Keylime verdict `trusted` is readable.

---

## Shot 3 — The whole chain, traced live (optional; edit to about 45 s)

**Caption:** One continuous run, traced live. Each bar is one step.

Second caption, when the red mark appears:
**Caption:** Keylime stopped on purpose → the next request is refused

**Narration:** Sandbox, watcher, two signatures, AWS, Keylime: all in one run.
When we stop Keylime, approved requests stop working. When it comes back, they
work again.

**Edit notes:** Cut the 35-second wait after Keylime is stopped; keep a
"35 seconds later" caption instead.

---

## Shot 4 — Catching a tampered machine (about 45 s)

**Caption 1 (clean run):** Clean machine → approved job runs

**Caption 2 (probe):** An unapproved program is run on the machine

**Caption 3 (detection):** Keylime flags the machine in about 2 seconds

**Caption 4 (denial):** Even with two approvals, the request is now denied

**Narration:** Linux fingerprints every program the machine runs, and Keylime
compares them to an approved list. One unexpected program, and the machine
loses its trust.

**Edit notes:** Show the Jaeger trace with `keylime.wait_for_detection`
selected, so its duration is visible.

---

## Closing card (5 s)

**Caption:** Every result here comes from a script in `experiments/` and is
saved in `results/`. Software TPM; hardware TPM (NitroTPM) is next.
