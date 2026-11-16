from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from agent_tool import model_agent
from agent_tool.nono_profile import MODEL_PHANTOM_VAR, MODEL_ROUTE, build_profile
from agent_tool.submit_request import RequestSubmissionError, load_schema, validate_request

DIGEST = "sha256:" + "a" * 64
CATALOG = {
    "targets": ["aws-keylime-demo-01"],
    "inputs": [
        {"name": "demo-payload.txt", "sha256": DIGEST},
        {"name": "other.txt", "sha256": "sha256:" + "b" * 64},
    ],
}


class FakeProxy(BaseHTTPRequestHandler):
    """Stands in for nono's credential proxy and the Messages API."""

    seen: list[dict[str, object]] = []
    tool_input: dict[str, str] = {}

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        FakeProxy.seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        reply = {
            "id": "msg_test",
            "model": body["model"],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "content": [{"type": "tool_use", "id": "t1", "name": "submit_request", "input": FakeProxy.tool_input}],
        }
        encoded = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args: object) -> None:
        pass


class ModelProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.outbox, self.inbox = root / "outbox", root / "inbox"
        self.outbox.mkdir()
        self.inbox.mkdir()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_model_profile_routes_only_through_the_credential_proxy(self) -> None:
        profile = build_profile(outbox=self.outbox, inbox=self.inbox, model_credential_env="EC528_ANTHROPIC_API_KEY")
        network = profile["network"]
        self.assertNotIn("block", network)
        self.assertEqual(network["credentials"], [MODEL_ROUTE])
        route = network["custom_credentials"][MODEL_ROUTE]
        self.assertEqual(route["upstream"], "https://api.anthropic.com")
        self.assertEqual(route["credential_key"], "env://EC528_ANTHROPIC_API_KEY")
        self.assertEqual(route["env_var"], MODEL_PHANTOM_VAR)
        self.assertNotIn("allow_domain", network)
        # The real key's variable is still stripped from the agent's environment.
        self.assertIn("*KEY*", profile["environment"]["deny_vars"])
        self.assertEqual(profile["filesystem"]["write"], [str(self.outbox.resolve())])

    def test_default_profile_is_still_networkless(self) -> None:
        self.assertEqual(build_profile(outbox=self.outbox, inbox=self.inbox)["network"], {"block": True})

    def test_claude_code_profile_injects_a_bearer_phantom_and_hides_the_real_token(self) -> None:
        binary_directory = Path(self.directory.name) / "claude-bin"
        binary_directory.mkdir()
        profile = build_profile(
            outbox=self.outbox,
            inbox=self.inbox,
            claude_code_token_env="EC528_CLAUDE_OAUTH_TOKEN",
            agent_read=[binary_directory],
        )
        route = profile["network"]["custom_credentials"]["anthropic"]
        self.assertEqual(profile["network"]["credentials"], ["anthropic"])
        self.assertEqual(route["credential_key"], "env://EC528_CLAUDE_OAUTH_TOKEN")
        self.assertEqual(route["env_var"], "CLAUDE_CODE_OAUTH_TOKEN")
        self.assertEqual((route["inject_header"], route["credential_format"]), ("Authorization", "Bearer {}"))
        environment = profile["environment"]
        self.assertIn("EC528_CLAUDE_OAUTH_TOKEN", environment["deny_vars"])
        self.assertNotIn("EC528_CLAUDE_OAUTH_TOKEN", environment["allow_vars"])
        self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", environment["allow_vars"])
        self.assertIn(str(binary_directory.resolve()), profile["filesystem"]["read"])
        self.assertEqual(profile["filesystem"]["write"], [str(self.outbox.resolve())])

    def test_agent_read_paths_cannot_expose_the_handoff(self) -> None:
        with self.assertRaises(RequestSubmissionError):
            build_profile(
                outbox=self.outbox,
                inbox=self.inbox,
                claude_code_token_env="EC528_CLAUDE_OAUTH_TOKEN",
                agent_read=[Path(self.directory.name)],
            )

    def test_only_one_model_route_at_a_time(self) -> None:
        with self.assertRaises(RequestSubmissionError):
            build_profile(
                outbox=self.outbox,
                inbox=self.inbox,
                model_credential_env="A_KEY_VAR",
                claude_code_token_env="EC528_CLAUDE_OAUTH_TOKEN",
            )

    def test_model_credential_variable_name_is_validated(self) -> None:
        with self.assertRaises(RequestSubmissionError):
            build_profile(outbox=self.outbox, inbox=self.inbox, model_credential_env="x; rm -rf /")


class ModelAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.outbox = root / "outbox"
        self.outbox.mkdir()
        self.task = root / "task.json"
        self.task.write_text(json.dumps({"instruction": "Checksum the demo payload.", "catalog": CATALOG}))
        self.transcript = root / "transcript.json"
        self.server = HTTPServer(("127.0.0.1", 0), FakeProxy)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        FakeProxy.seen = []
        FakeProxy.tool_input = {
            "target": "aws-keylime-demo-01",
            "input_name": "demo-payload.txt",
            "expected_input_sha256": DIGEST,
        }
        self.environment = {
            "EC528_MODEL_BASE_URL": f"http://127.0.0.1:{self.server.server_address[1]}/{MODEL_ROUTE}",
            MODEL_PHANTOM_VAR: "phantom-session-token",
        }
        self.schema = load_schema(Path(__file__).resolve().parents[1] / "src" / "request_schema.json")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.directory.cleanup()

    def run_agent(self, *extra: str) -> int:
        with mock.patch.dict(os.environ, self.environment, clear=True):
            return model_agent.main([
                "--task", str(self.task), "--outbox", str(self.outbox),
                "--transcript", str(self.transcript), *extra,
            ])

    def test_model_choice_becomes_a_schema_valid_outbox_request(self) -> None:
        self.assertEqual(self.run_agent(), 0)
        files = list(self.outbox.glob("*.json"))
        self.assertEqual(len(files), 1)
        request = json.loads(files[0].read_text())
        validate_request(request, self.schema)
        self.assertEqual(request["input_name"], "demo-payload.txt")
        call = FakeProxy.seen[0]
        self.assertEqual(call["path"], f"/{MODEL_ROUTE}/v1/messages")
        self.assertEqual(call["headers"]["x-api-key"], "phantom-session-token")
        self.assertEqual(call["body"]["tool_choice"], {"type": "any"})
        transcript = json.loads(self.transcript.read_text())
        self.assertEqual(transcript["tool_input"], FakeProxy.tool_input)

    def test_replay_reproduces_the_request_without_the_model(self) -> None:
        self.assertEqual(self.run_agent(), 0)
        recorded = self.outbox.parent / "recorded.json"
        recorded.write_text(self.transcript.read_text())
        for file in self.outbox.glob("*.json"):
            file.unlink()
        FakeProxy.seen = []
        self.assertEqual(self.run_agent("--replay", str(recorded)), 0)
        self.assertEqual(FakeProxy.seen, [])
        request = json.loads(next(self.outbox.glob("*.json")).read_text())
        self.assertEqual(request["target"], "aws-keylime-demo-01")

    def test_choices_outside_the_catalog_are_refused(self) -> None:
        FakeProxy.tool_input = {**FakeProxy.tool_input, "target": "attacker-node"}
        self.assertEqual(self.run_agent(), 1)
        self.assertEqual(list(self.outbox.glob("*.json")), [])

    def test_submit_mode_publishes_one_catalog_request_for_claude_code(self) -> None:
        arguments = [
            "--submit", "--task", str(self.task), "--outbox", str(self.outbox),
            "--transcript", str(self.transcript),
            "--target", "aws-keylime-demo-01", "--input-name", "demo-payload.txt", "--sha256", DIGEST,
        ]
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(model_agent.main(arguments), 0)
            # A second submission in the same session is refused.
            self.assertEqual(model_agent.main(arguments), 1)
        self.assertEqual(len(list(self.outbox.glob("*.json"))), 1)
        transcript = json.loads(self.transcript.read_text())
        self.assertEqual(transcript["agent"], "claude-code")
        validate_request(transcript["published_request"], self.schema)

    def test_submit_mode_refuses_targets_outside_the_catalog(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            code = model_agent.main([
                "--submit", "--task", str(self.task), "--outbox", str(self.outbox),
                "--transcript", str(self.transcript),
                "--target", "attacker-node", "--input-name", "demo-payload.txt", "--sha256", DIGEST,
            ])
        self.assertEqual(code, 1)
        self.assertEqual(list(self.outbox.glob("*.json")), [])

    def test_agent_refuses_a_non_loopback_model_endpoint(self) -> None:
        self.environment["EC528_MODEL_BASE_URL"] = "https://api.anthropic.com/ec528_model"
        self.assertEqual(self.run_agent(), 1)
        self.assertEqual(FakeProxy.seen, [])


if __name__ == "__main__":
    unittest.main()
