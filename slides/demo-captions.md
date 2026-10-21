# Demo 2 recording sequence

The submitted [69-second recording](demo-2.mp4) is silent. It combines the
redesigned dashboard, the live Jaeger trace, and short context cards for the
AWS run and IMA tamper result. Only sanitized evidence is displayed.

The sequence is:

1. a request without a receipt is denied;
2. the first approval remains pending;
3. the second distinct approval issues the receipt;
4. changing the approved target is denied;
5. the exact action runs after a fresh AWS Keylime `PASS`; and
6. replaying the consumed receipt is denied;
7. the end-to-end AWS trace is shown; and
8. an IMA-detected node tamper causes a fresh approved request to fail closed.

The cloud stack shown in the recording was deleted after the evidence was
saved. The deeper IMA tamper result is reproducible with `make ima-tamper` and
recorded in [`../results/ima-tamper.json`](../results/ima-tamper.json).
