from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from controller.outbox_watcher import main as watcher_main
from controller.policy_digest import (
    PolicyDigestError,
    canonical_policy_json,
    policy_digest,
    policy_version_from_files,
    sha256_digest,
)

# The same inputs and expected value appear in tests-js/policy_digest.test.mjs.
VECTOR_KEYLIME = "sha256:" + "ab" * 32
VECTOR_APPROVAL = {
    "@version": "EC528-APPROVAL-POLICY-v1",
    "issuer_keys": ["issuer-a"],
    "approver_keys": {
        "k2": {"approver_id": "ep:approver:café", "key_class": "A"},
        "k1": {"approver_id": "ep:approver:ops", "key_class": "A"},
    },
    "quorum_policies": {
        "mcp.execute_approved_workload": {
            "distinct_humans": True,
            "mode": "threshold",
            "required": 2,
            "window_sec": 900,
        }
    },
    "rp_id": "127.0.0.1",
    "allowed_origins": ["http://127.0.0.1"],
}
VECTOR_EXPECTED = "pd1-1f60f071d37fe24373a5bbf0ed0497ab3fba7ec2ac5a9c15933c603562ad"


class PolicyDigestTests(unittest.TestCase):
    def test_matches_the_cross_language_vector(self) -> None:
        self.assertEqual(
            policy_digest(
                keylime_policy_sha256=VECTOR_KEYLIME,  # gitleaks:allow
                approval_policy=VECTOR_APPROVAL,
            ),
            VECTOR_EXPECTED,
        )

    def test_key_order_does_not_matter_but_content_does(self) -> None:
        reordered = dict(reversed(list(VECTOR_APPROVAL.items())))
        self.assertEqual(
            policy_digest(
                keylime_policy_sha256=VECTOR_KEYLIME,  # gitleaks:allow
                approval_policy=reordered,
            ),
            VECTOR_EXPECTED,
        )
        changed = copy.deepcopy(VECTOR_APPROVAL)
        changed["quorum_policies"]["mcp.execute_approved_workload"]["required"] = 1
        self.assertNotEqual(
            policy_digest(
                keylime_policy_sha256=VECTOR_KEYLIME,  # gitleaks:allow
                approval_policy=changed,
            ),
            VECTOR_EXPECTED,
        )
        self.assertNotEqual(
            policy_digest(
                keylime_policy_sha256="sha256:" + "cd" * 32,
                approval_policy=VECTOR_APPROVAL,
            ),
            VECTOR_EXPECTED,
        )

    def test_unsupported_content_is_refused(self) -> None:
        with self.assertRaises(PolicyDigestError):
            canonical_policy_json({"n": 1.5})
        with self.assertRaises(PolicyDigestError):
            canonical_policy_json({"é": 1})
        with self.assertRaises(PolicyDigestError):
            canonical_policy_json({"n": object()})
        with self.assertRaises(PolicyDigestError):
            policy_digest(keylime_policy_sha256="nope", approval_policy=VECTOR_APPROVAL)

    def test_files_hash_the_keylime_policy_bytes_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keylime = root / "keylime-policy.json"
            approval = root / "approval-policy.json"
            body = b'{"allowlist":["/usr/bin/sha256sum"]}\n'
            keylime.write_bytes(body)
            approval.write_text(json.dumps(VECTOR_APPROVAL), encoding="utf-8")
            expected = policy_digest(
                keylime_policy_sha256=sha256_digest(body), approval_policy=VECTOR_APPROVAL
            )
            self.assertEqual(
                policy_version_from_files(keylime_policy=keylime, approval_policy=approval),
                expected,
            )
            keylime.write_bytes(body + b"\n")
            self.assertNotEqual(
                policy_version_from_files(keylime_policy=keylime, approval_policy=approval),
                expected,
            )
            approval.write_text("[]", encoding="utf-8")
            with self.assertRaises(PolicyDigestError):
                policy_version_from_files(keylime_policy=keylime, approval_policy=approval)


class WatcherPolicyOptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        for name in ("outbox", "inbox", "storage", "inputs"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "artifact").write_bytes(b"trusted workload artifact\n")
        self.keylime = self.root / "keylime-policy.json"
        self.keylime.write_bytes(b'{"allowlist":[]}\n')
        self.approval = self.root / "approval-policy.json"
        self.approval.write_text(json.dumps(VECTOR_APPROVAL), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def argv(self, *extra: str) -> list[str]:
        return [
            "--outbox", str(self.root / "outbox"),
            "--inbox", str(self.root / "inbox"),
            "--storage", str(self.root / "storage"),
            "--input-root", str(self.root / "inputs"),
            "--artifact", str(self.root / "artifact"),
            "--allowed-target", "azure-vm-01",
            *extra,
        ]

    def test_label_and_policy_files_are_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit):
            watcher_main(self.argv("--policy-version", "demo-2.1", "--keylime-policy", str(self.keylime)))

    def test_keylime_policy_requires_the_approval_policy(self) -> None:
        self.assertEqual(watcher_main(self.argv("--keylime-policy", str(self.keylime))), 1)

    def test_approval_policy_alone_is_refused(self) -> None:
        self.assertEqual(
            watcher_main(self.argv("--policy-version", "demo-2.1", "--approval-policy", str(self.approval))),
            1,
        )

    def test_policy_files_and_legacy_label_both_run(self) -> None:
        self.assertEqual(
            watcher_main(self.argv("--keylime-policy", str(self.keylime), "--approval-policy", str(self.approval))),
            0,
        )
        self.assertEqual(watcher_main(self.argv("--policy-version", "demo-2.1")), 0)

    def test_unreadable_policy_file_fails_closed(self) -> None:
        self.assertEqual(
            watcher_main(self.argv("--keylime-policy", str(self.root / "missing"), "--approval-policy", str(self.approval))),
            1,
        )


if __name__ == "__main__":
    unittest.main()
