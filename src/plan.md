# Project Plan: Nono → EMILIA Handoff

## Context
Source documents:
- `EC528-fall26-zero-trust.pdf`, the project summary
- `zero-trust/docs/design-proposal.md` on the `demo-1` branch

They describe this pipeline: a Nono-confined AI agent → EMILIA Gate 2-of-3 quorum approval → a Keylime-attested executor on a MOC VM or bare-metal node. In the proposal, the agent sends a "structured request" to the controller/Gate. The agent has no direct path to the executor, SSH or cloud management.

**Open question:** how does the agent's intent leave the sandbox in a form EMILIA can review?

**Approach:** the agent writes every action it wants to take to a structured file, the outbox. A trusted component parses that file, validates it, and submits it to EMILIA Gate.

## Design rules

1. **Nono enforces the boundary, not the prompt.** The Nono profile grants write access only to an outbox directory and a scratch workdir. It allows no network except the inference endpoint, if one is needed. The agent can still print to the terminal or edit scratch files. That doesn't matter, because the outbox is the only channel with any effect outside the sandbox.
2. **JSON with a strict schema, not CSV.** Requests carry argument lists, digests, nested stages (bootstrap + workload) and a schema version. Validate them with JSON Schema using `additionalProperties: false`, so unknown or ambiguous fields are rejected (proposal §2.3).
3. **The agent requests actions. It does not describe changes.** It picks an allowlisted `operation` and supplies typed parameters. It sends no shell strings, diffs or free-form commands. This matches the proposal's narrow workload scope.
4. **The parser validates and maps. It never interprets.** It runs outside the sandbox in the trusted control plane. It rejects malformed input and never guesses intent. Never use an LLM as the parser, because that would bring back prompt injection.
5. **The trusted side computes the security-relevant fields.** The controller hashes the artifact and input itself, assigns the occurrence ID, sets expiry and the policy version, and pins the target. Any of these fields supplied by the agent are claims that must match.
6. **Harden the file handoff:**
   - Atomic write: the agent writes `*.tmp`, then renames it to `*.json`.
   - Size cap; reject symlinks (`O_NOFOLLOW`).
   - Copy the file into controller-owned storage before parsing.
   - One file = one request, never reprocessed.
7. **Return channel.** A read-only inbox, or a status file per request ID, lets the agent see `PENDING_APPROVAL` / `DENIED` / `SUCCEEDED` without any other access.

## Data flow

```
Agent (in Nono) --submit_request--> outbox/<id>.json
     ^                                   |
     | read-only status                  v
inbox/<id>.status   <---   outbox_watcher (trusted)
                              | validate, hash, assign IDs, canonicalize
                              v
                        emilia_adapter --> EMILIA Gate (2-of-3 quorum)
                                                |
                                                v
                                  Keylime attestation --> executor
```

## Components (Demo 2/3 scope)

| Component | Purpose |
| --- | --- |
| `src/request_schema.json` | Schema the agent's requests must follow: operation enum, params, schema_version |
| `src/agent_tool/submit_request.py` | Helper the agent calls. Validates locally for fast feedback and writes atomically to the outbox. For convenience only; it is not a security boundary. |
| `src/controller/outbox_watcher.py` | Trusted watcher: safe ingest, strict validation, digests and IDs, builds the canonical action manifest |
| `src/controller/emilia_adapter.py` | Maps the manifest to the pinned EMILIA revision's action/receipt format and submits it to Gate |
| Nono profile | Outbox write-only, inbox read-only, deny everything else |

## Open items
- [ ] **Check EMILIA Gate's actual action input format and canonicalization profile** in the pinned revision. The adapter design depends on it.
- [ ] Define the initial operation allowlist (e.g. the checksum workload and its no-op mode).
- [ ] Decide on the outbox/inbox locations on the host and their ownership/permissions.
- [ ] Confirm that Nono can express write-only outbox and read-only inbox rules.

## Verification
- **Unit tests:** reject malformed JSON, unknown fields, oversized files, symlinks, partial writes and digest mismatches.
- **Confinement tests (inside Nono):** writing outside the outbox, reaching the executor or Gate directly, and reading credentials all fail. A valid outbox request reaches `PENDING_APPROVAL` in Gate. Feeds `experiments/demo3_confinement.sh`.
- **End-to-end:** agent request → file → watcher → Gate pending → 2 fixture signatures → admitted.
