from __future__ import annotations

import json
import unittest
from pathlib import Path

from controller.emilia_adapter import (
    DEFAULT_RECEIPT_MAX_AGE_SEC,
    EmiliaAdapterError,
    receipt_required_challenge,
)
from security_parameters import SECURITY_PARAMETERS

MANIFEST = Path(__file__).resolve().parents[1] / "public" / ".well-known" / "agent-actions.json"
ACTION = {
    "action_type": "workload.execute",
    "operation": "checksum.sha256",
    "target": "azure-vm-01",
    "artifact_sha256": "sha256:" + "a" * 64,
    "input_sha256": "sha256:" + "b" * 64,
    "occurrence_id": "d24f4f93-e555-4d48-93aa-a2c16c53a24f",
    "policy_version": "demo-2.1",
}


class ReceiptTtlTests(unittest.TestCase):
    def test_challenge_default_matches_the_published_manifest(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        required = [a for a in manifest["actions"] if a.get("receipt_required")]
        self.assertGreaterEqual(len(required), 1)
        self.assertTrue(all(
            action["max_age_sec"] == SECURITY_PARAMETERS["receipt_max_age_sec"]
            for action in required
        ))
        challenge = receipt_required_challenge(ACTION)
        self.assertEqual(challenge["required"]["max_age_sec"], DEFAULT_RECEIPT_MAX_AGE_SEC)

    def test_default_is_short(self) -> None:
        self.assertLessEqual(DEFAULT_RECEIPT_MAX_AGE_SEC, 120)

    def test_receipt_and_approval_windows_are_distinct_central_settings(self) -> None:
        self.assertEqual(DEFAULT_RECEIPT_MAX_AGE_SEC, 120)
        self.assertEqual(SECURITY_PARAMETERS["approval_window_sec"], 900)
        self.assertLess(
            SECURITY_PARAMETERS["receipt_max_age_sec"],
            SECURITY_PARAMETERS["approval_window_sec"],
        )

    def test_max_age_can_be_set_and_is_bounded(self) -> None:
        self.assertEqual(receipt_required_challenge(ACTION, 900)["required"]["max_age_sec"], 900)
        for bad in (0, -1, 86_401, True, 1.5, "120"):
            with self.assertRaises(EmiliaAdapterError):
                receipt_required_challenge(ACTION, bad)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
