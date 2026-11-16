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

## IMA tamper experiment (`make ima-tamper`)

Runs against the AWS node from `infra/aws` and writes `results/ima-tamper.json`.
A clean node runs the approved workload. Then an unapproved program is executed
on the node, Keylime's IMA runtime policy must mark the node as failed, and the
next fully approved request must be denied. The node stays failed afterwards
(the IMA log keeps the probe until reboot), so run `infra/aws/teardown.sh` next.

Additional limitations for this experiment:

- IMA measurements come from the real kernel but are copied into the swtpm
  PCR 10 by `keylime_ima_emulator`; root on the node could forge them.
- The runtime policy is generated on the node from its own filesystem at boot
  (trust on first use).
- Only executed and executable-mapped files are measured. tmpfs and other
  in-memory filesystems are not measured, and the SSM per-command script
  directory is excluded.

## Tracing with OpenTelemetry (optional)

The cloud experiments emit OpenTelemetry spans when
`OTEL_EXPORTER_OTLP_ENDPOINT` is set; otherwise tracing is off and nothing
changes. Each scenario, Keylime MCP call, SSM command, tunnel, and nono step
becomes a span. Spans hold only step names, outcomes, HTTP statuses, refusal
reasons, and public IDs or digests, never tokens, receipts, or raw Keylime
responses.

```bash
make jaeger                     # start a local Jaeger (UI at http://127.0.0.1:16686)
make trace-replay               # show already-recorded runs from results/*.json
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 make ima-tamper   # trace a live run
```

Replayed runs carry `ec528.replayed=true` and use the timestamps stored in the
results file. When searching in Jaeger, widen "Lookback" to cover the run date.
