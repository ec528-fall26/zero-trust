# Experiments

One script per claim. Each script should be runnable from the repository root,
print what it is measuring, and finish in a bounded amount of time.

Every script here must have a matching entry in
[`../docs/design-document.md`](../docs/design-document.md) stating what it
supports, how long it takes, and what output to expect.

All experiment results carry these scope limitations:

- swtpm is not a hardware root of trust.
- The Keylime verifier, registrar, agent, swtpm, and MCP all run on the same
  instance they are checking. This proves the protocol works, not independent
  attestation.
- The three EMILIA signer keys are on one machine. This proves the protocol
  works, not independent human approval.
