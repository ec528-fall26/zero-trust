# Approver roster

Each file here is one person's **public** approver record. The controller pins
these keys and the 2-of-3 quorum policy; it never holds an approver's private key.

To enroll, on your own machine:

```bash
npm ci
node tools/approver.mjs keygen --role <operator|security|reviewer> --name "Your Name"
```

This writes your private key to `~/.ec528-approver/approver-key.pem` (mode 0600,
never share it) and your public record to `~/.ec528-approver/approver.json`.
Open a pull request adding that record as `config/approvers/<role>.json`. The
pull request is the enrollment record: reviewers can see who added which key.

The roster needs at least three people with distinct keys. Only `.json` files are
read.
