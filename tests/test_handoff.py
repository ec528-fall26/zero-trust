from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_tool.submit_request import (
    RequestSubmissionError,
    build_request,
    load_schema,
    publish_request,
)
from agent_tool.nono_profile import build_profile
from controller.emilia_adapter import action_hash, receipt_required_challenge
from controller.outbox_watcher import (
    ControllerPolicy,
    OutboxError,
    process_request,
    run_once,
)


class HandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.outbox = self.root / "outbox"
        self.inbox = self.root / "inbox"
        self.storage = self.root / "storage"
        self.inputs = self.root / "inputs"
        for directory in (self.outbox, self.inbox, self.storage, self.inputs):
            directory.mkdir(mode=0o700)
        self.input_file = self.inputs / "payload.bin"
        self.input_file.write_bytes(b"fixed workload input\n")
        self.artifact = self.root / "checksum-workload"
        self.artifact.write_bytes(b"trusted workload artifact\n")
        self.schema_path = Path(__file__).resolve().parents[1] / "src" / "request_schema.json"
        self.schema = load_schema(self.schema_path)
        self.input_digest = f"sha256:{hashlib.sha256(self.input_file.read_bytes()).hexdigest()}"
        self.policy = ControllerPolicy(
            artifact=self.artifact,
            input_root=self.inputs,
            allowed_targets=frozenset({"azure-vm-01"}),
            policy_version="demo-2.1",
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def request(self, **changes: str) -> dict[str, str]:
        values = {
            "operation": "checksum.sha256",
            "target": "azure-vm-01",
            "input_name": self.input_file.name,
            "expected_input_sha256": self.input_digest,
            "request_id": "784f8fb4-60c7-43d7-9911-65d5e9afbbef",
        }
        values.update(changes)
        return build_request(**values)

    def test_agent_publishes_one_canonical_request(self) -> None:
        request = self.request()
        destination = publish_request(request, schema=self.schema, outbox=self.outbox)

        self.assertEqual(destination.name, f"{request['request_id']}.json")
        self.assertEqual(json.loads(destination.read_text(encoding="ascii")), request)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(RequestSubmissionError, "atomically publish"):
            publish_request(request, schema=self.schema, outbox=self.outbox)

    def test_unknown_request_field_is_rejected(self) -> None:
        request = self.request()
        request["shell_command"] = "curl metadata.azure.internal"

        with self.assertRaisesRegex(RequestSubmissionError, "validation failed"):
            publish_request(request, schema=self.schema, outbox=self.outbox)

    def test_watcher_builds_trusted_action_and_receipt_challenge(self) -> None:
        request = self.request()
        source = publish_request(request, schema=self.schema, outbox=self.outbox)

        status = process_request(
            source,
            schema=self.schema,
            storage=self.storage,
            inbox=self.inbox,
            policy=self.policy,
        )

        self.assertFalse(source.exists())
        action_path = self.storage / f"{request['request_id']}.action.json"
        action = json.loads(action_path.read_text(encoding="utf-8"))
        expected_artifact_digest = (
            f"sha256:{hashlib.sha256(self.artifact.read_bytes()).hexdigest()}"
        )
        self.assertEqual(action["artifact_sha256"], expected_artifact_digest)
        self.assertEqual(action["input_sha256"], self.input_digest)
        self.assertEqual(action["target"], "azure-vm-01")
        challenge = status["challenge"]
        self.assertEqual(challenge["status"], 428)
        self.assertEqual(challenge["required"]["action_hash"], action_hash(action))
        self.assertTrue((self.inbox / f"{request['request_id']}.status.json").exists())

    def test_input_digest_mismatch_fails_closed(self) -> None:
        request = self.request(expected_input_sha256=f"sha256:{'0' * 64}")
        source = publish_request(request, schema=self.schema, outbox=self.outbox)

        with self.assertRaisesRegex(OutboxError, "digest does not match"):
            process_request(
                source,
                schema=self.schema,
                storage=self.storage,
                inbox=self.inbox,
                policy=self.policy,
            )

        self.assertFalse(source.exists())
        self.assertTrue((self.storage / f"{request['request_id']}.request.json").exists())
        self.assertFalse((self.storage / f"{request['request_id']}.action.json").exists())

    def test_unallowlisted_target_fails_closed(self) -> None:
        request = self.request(target="azure-vm-attacker")
        source = publish_request(request, schema=self.schema, outbox=self.outbox)

        with self.assertRaisesRegex(OutboxError, "not allowlisted"):
            process_request(
                source,
                schema=self.schema,
                storage=self.storage,
                inbox=self.inbox,
                policy=self.policy,
            )

    def test_symlink_request_is_rejected(self) -> None:
        request = self.request()
        outside = self.root / "outside.json"
        outside.write_text(json.dumps(request), encoding="utf-8")
        source = self.outbox / f"{request['request_id']}.json"
        source.symlink_to(outside)

        with self.assertRaisesRegex(OutboxError, "safely open"):
            process_request(
                source,
                schema=self.schema,
                storage=self.storage,
                inbox=self.inbox,
                policy=self.policy,
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires POSIX")
    def test_fifo_request_is_rejected_without_blocking(self) -> None:
        request = self.request()
        source = self.outbox / f"{request['request_id']}.json"
        os.mkfifo(source, mode=0o600)

        with self.assertRaisesRegex(OutboxError, "bounded regular file"):
            process_request(
                source,
                schema=self.schema,
                storage=self.storage,
                inbox=self.inbox,
                policy=self.policy,
            )

    def test_watcher_continues_after_an_invalid_filename(self) -> None:
        invalid = self.outbox / "agent-chosen-name.json"
        invalid.write_text("{}", encoding="ascii")
        request = self.request()
        publish_request(request, schema=self.schema, outbox=self.outbox)

        results = run_once(
            outbox=self.outbox,
            schema=self.schema,
            storage=self.storage,
            inbox=self.inbox,
            policy=self.policy,
        )

        self.assertEqual(len(results), 2)
        self.assertFalse(invalid.exists())
        self.assertTrue((self.storage / f"{request['request_id']}.action.json").exists())

    def test_challenge_hash_changes_with_material_action(self) -> None:
        action = {
            "action_type": "workload.execute",
            "operation": "checksum.sha256",
            "target": "azure-vm-01",
            "artifact_sha256": f"sha256:{'a' * 64}",
            "input_sha256": f"sha256:{'b' * 64}",
            "occurrence_id": "784f8fb4-60c7-43d7-9911-65d5e9afbbef",
            "policy_version": "demo-2.1",
        }
        changed = {**action, "target": "azure-vm-02"}

        self.assertNotEqual(
            receipt_required_challenge(action)["required"]["action_hash"],
            receipt_required_challenge(changed)["required"]["action_hash"],
        )
        self.assertEqual(
            action_hash(action),
            "sha256:785da0d84c7823d29c35e582f049e5e9bbe06bde82895d915ef2caa410989ff8",
        )

    def test_nono_profile_has_one_way_handoff_and_no_network(self) -> None:
        profile = build_profile(outbox=self.outbox, inbox=self.inbox)

        self.assertEqual(profile["filesystem"]["write"], [str(self.outbox.resolve())])
        self.assertEqual(profile["filesystem"]["read"], [str(self.inbox.resolve())])
        self.assertTrue(profile["network"]["block"])
        self.assertFalse(profile["security"]["capability_elevation"])
        self.assertIn("EMILIA_*", profile["environment"]["deny_vars"])

    def test_nono_profile_rejects_overlapping_handoff_paths(self) -> None:
        nested = self.outbox / "inbox"
        nested.mkdir()

        with self.assertRaisesRegex(RequestSubmissionError, "must not overlap"):
            build_profile(outbox=self.outbox, inbox=nested)


if __name__ == "__main__":
    unittest.main()


class NodeWorkloadConsistencyTest(unittest.TestCase):
    """The dashboard, experiments and AWS template must use identical bytes."""

    REPOSITORY = Path(__file__).resolve().parents[1]

    def test_workload_files_match_the_aws_template(self) -> None:
        workload = self.REPOSITORY / "infra" / "aws" / "workload"
        template = (self.REPOSITORY / "infra" / "aws" / "main.yaml").read_text(encoding="utf-8")
        indent = " " * 10
        for name, start, end in (
            ("checksum.sh", "cat > /opt/ec528/workloads/checksum.sh <<'WORKLOAD'\n", f"\n{indent}WORKLOAD\n"),
        ):
            body = template.split(start, 1)[1].split(end, 1)[0]
            installed = "\n".join(line[len(indent):] for line in body.split("\n")) + "\n"
            self.assertEqual(installed.encode(), (workload / name).read_bytes())
        self.assertIn(
            "printf '%s\\n' 'EC528 approved workload payload' > /opt/ec528/inputs/demo-payload.txt",
            template,
        )
        self.assertEqual(
            (workload / "demo-payload.txt").read_bytes(), b"EC528 approved workload payload\n"
        )

    def test_experiments_embed_the_same_workload(self) -> None:
        artifact = (self.REPOSITORY / "infra" / "aws" / "workload" / "checksum.sh").read_text()
        embedded = artifact.replace("\n", "\\n")
        for experiment in ("demo2_end_to_end.mjs", "ima_tamper.mjs"):
            source = (self.REPOSITORY / "experiments" / experiment).read_text()
            self.assertIn(embedded, source.replace("'\n      '", "").replace("',\n      '", ""), experiment)
