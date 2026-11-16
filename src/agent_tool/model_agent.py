"""Model-driven agent that runs inside the nono sandbox.

It asks a Claude model to choose the workload request for a task, then
publishes that request to the outbox exactly as submit_request.py does.  It
uses only the standard library, because the sandbox cannot read the
project's virtualenv.

The sandbox never holds the real Anthropic API key.  nono's credential proxy
(see nono_profile.py --model-credential-env) gives the agent a loopback base
URL and a per-session phantom token; the proxy, outside the sandbox, swaps
the phantom for the real key and forwards only to api.anthropic.com.

    python3 model_agent.py --task task.json --outbox OUTBOX --transcript t.json
    python3 model_agent.py --task task.json --outbox OUTBOX --replay t.json
    python3 model_agent.py --probe --forbidden-port 3000 [--forbidden-path P ...]

With Claude Code as the agent, this file is its only way to act: Claude Code
may run exactly `python3 model_agent.py --submit ...` and nothing else.

    python3 model_agent.py --submit --task task.json --outbox OUTBOX \
        --transcript t.json --target T --input-name N --sha256 sha256:...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

SCHEMA_VERSION = "ec528.nono.request.v1"
OPERATION = "checksum.sha256"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
ROUTE = "ec528_model"
PHANTOM_VAR = "EC528_MODEL_PHANTOM"
DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_TOKENS = 1024
ANTHROPIC_VERSION = "2023-06-01"

SYSTEM_PROMPT = (
    "You are an operations agent confined in a sandbox. You cannot run "
    "workloads yourself. You may only ask for one, by calling submit_request "
    "exactly once with the target node and input file the task needs, chosen "
    "from the catalog. Two human approvers will review the request, and the "
    "node will only run it if its attestation is fresh. Never invent targets, "
    "file names or digests that are not in the catalog."
)


class AgentError(Exception):
    pass


def _endpoint() -> tuple[str, str]:
    """Find the proxy route nono set up; refuse anything but loopback."""
    base = os.environ.get(f"{ROUTE.upper()}_BASE_URL")
    if not base:
        for name, value in os.environ.items():
            if name.endswith("_BASE_URL") and value.rstrip("/").endswith(f"/{ROUTE}"):
                base = value
                break
    phantom = os.environ.get(PHANTOM_VAR)
    if not base or not phantom:
        raise AgentError("no nono credential route: run under a profile made with --model-credential-env")
    host = urllib.parse.urlsplit(base).hostname
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise AgentError("model base URL is not the local nono proxy")
    return base.rstrip("/"), phantom


def _tool(catalog: dict[str, object]) -> dict[str, object]:
    inputs = catalog["inputs"]
    return {
        "name": "submit_request",
        "description": (
            "Ask the controller to run the sha256 checksum workload on a node. "
            "The request is reviewed by two humans before anything runs."
        ),
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "input_name", "expected_input_sha256"],
            "properties": {
                "target": {"type": "string", "enum": list(catalog["targets"])},
                "input_name": {"type": "string", "enum": [entry["name"] for entry in inputs]},
                "expected_input_sha256": {
                    "type": "string",
                    "enum": [entry["sha256"] for entry in inputs],
                },
            },
        },
    }


def _call_model(body: dict[str, object]) -> dict[str, object]:
    base, phantom = _endpoint()
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{base}/v1/messages",
        data=data,
        method="POST",
        headers={
            "content-type": "application/json",
            "anthropic-version": ANTHROPIC_VERSION,
            "x-api-key": phantom,
        },
    )
    # nono's proxy on Linux can refuse back-to-back connections; retry those.
    for attempt in range(5):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read(2048).decode("utf-8", "replace")
            raise AgentError(f"model API returned HTTP {error.code}: {detail}") from error
        except (urllib.error.URLError, ConnectionError) as error:
            if attempt == 4:
                raise AgentError(f"model API unreachable: {error}") from error
            time.sleep(0.5 * (attempt + 1))
    raise AgentError("model API unreachable")


def choose_request(task: dict[str, object], model: str) -> tuple[dict[str, str], dict[str, object]]:
    catalog = task["catalog"]
    body = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "tools": [_tool(catalog)],
        "tool_choice": {"type": "any"},
        "messages": [{
            "role": "user",
            "content": (
                f"Task: {task['instruction']}\n\n"
                f"Catalog (targets and inputs you may use):\n{json.dumps(catalog, indent=2)}"
            ),
        }],
    }
    response = _call_model(body)
    calls = [block for block in response.get("content", []) if block.get("type") == "tool_use"]
    if len(calls) != 1 or calls[0].get("name") != "submit_request":
        raise AgentError("the model did not make exactly one submit_request call")
    transcript = {
        "schema": "ec528.model-agent-transcript.v1",
        "model_requested": model,
        "request_body": body,
        "response": {
            key: response.get(key)
            for key in ("id", "model", "stop_reason", "usage", "content")
        },
        "tool_input": calls[0].get("input"),
    }
    return calls[0].get("input"), transcript


def build_request(tool_input: object, catalog: dict[str, object]) -> dict[str, str]:
    if not isinstance(tool_input, dict) or set(tool_input) != {"target", "input_name", "expected_input_sha256"}:
        raise AgentError("tool input has the wrong fields")
    target = tool_input["target"]
    name = tool_input["input_name"]
    digest = tool_input["expected_input_sha256"]
    if not (isinstance(target, str) and TARGET.fullmatch(target) and target in catalog["targets"]):
        raise AgentError("target is not in the catalog")
    if not (isinstance(name, str) and NAME.fullmatch(name)):
        raise AgentError("input name is invalid")
    if not (isinstance(digest, str) and DIGEST.fullmatch(digest)):
        raise AgentError("digest is invalid")
    # Only a claim: the trusted watcher recomputes the digest from the bytes.
    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": str(uuid.uuid4()),
        "operation": OPERATION,
        "target": target,
        "input_name": name,
        "expected_input_sha256": digest,
    }


def publish(request: dict[str, str], outbox: Path) -> Path:
    """Atomic, no-follow publish; same protocol as submit_request.publish_request."""
    encoded = json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    temporary = outbox / f".{request['request_id']}.{uuid.uuid4().hex}.tmp"
    destination = outbox / f"{request['request_id']}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, destination, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def probe(forbidden_ports: list[int], forbidden_paths: list[str]) -> dict[str, object]:
    """Confinement checks run from inside the sandbox.  Every check must fail closed."""
    def connects(host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except OSError:
            return False

    def readable(path: str) -> bool:
        try:
            if os.path.isdir(path):
                os.listdir(path)
            else:
                with open(path, "rb") as handle:
                    handle.read(1)
            return True
        except OSError:
            return False

    real_key_visible = any(value.startswith("sk-ant-") for value in os.environ.values())
    results = {
        "real_api_key_in_environment": real_key_visible,
        "direct_anthropic_api_reachable": connects("api.anthropic.com", 443),
        "other_internet_host_reachable": connects("example.com", 443),
        "forbidden_ports_reachable": {str(port): connects("127.0.0.1", port) for port in forbidden_ports},
        "forbidden_paths_readable": {path: readable(path) for path in forbidden_paths},
    }
    results["passed"] = not (
        real_key_visible
        or results["direct_anthropic_api_reachable"]
        or results["other_internet_host_reachable"]
        or any(results["forbidden_ports_reachable"].values())
        or any(results["forbidden_paths_readable"].values())
    )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="model-agent")
    parser.add_argument("--task", type=Path)
    parser.add_argument("--outbox", type=Path)
    parser.add_argument("--transcript", type=Path)
    parser.add_argument("--replay", type=Path, help="reuse a recorded model decision; no network")
    parser.add_argument("--model", default=os.environ.get("EC528_MODEL_NAME", DEFAULT_MODEL))
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--submit", action="store_true", help="publish one request chosen by an outside agent")
    parser.add_argument("--target")
    parser.add_argument("--input-name")
    parser.add_argument("--sha256")
    parser.add_argument("--forbidden-port", type=int, action="append", default=[])
    parser.add_argument("--forbidden-path", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.probe:
            print(json.dumps(probe(args.forbidden_port, args.forbidden_path), sort_keys=True))
            return 0
        if not args.task or not args.outbox:
            raise AgentError("--task and --outbox are required")
        task = json.loads(args.task.read_text(encoding="utf-8"))
        if args.submit:
            # One request per session: a second --submit is refused.
            if args.transcript and args.transcript.exists():
                raise AgentError("a request was already submitted in this session")
            tool_input = {
                "target": args.target,
                "input_name": args.input_name,
                "expected_input_sha256": args.sha256,
            }
            transcript = {
                "schema": "ec528.model-agent-transcript.v1",
                "agent": "claude-code",
                "tool_input": tool_input,
            }
        elif args.replay:
            transcript = json.loads(args.replay.read_text(encoding="utf-8"))
            tool_input = transcript["tool_input"]
            transcript = {**transcript, "replayed": True}
        else:
            tool_input, transcript = choose_request(task, args.model)
        request = build_request(tool_input, task["catalog"])
        destination = publish(request, args.outbox)
        transcript["published_request"] = request
        if args.transcript:
            args.transcript.write_text(json.dumps(transcript, indent=2), encoding="utf-8")
        print(json.dumps({"request_id": request["request_id"], "outbox_file": destination.name}))
        return 0
    except (AgentError, OSError, KeyError, ValueError) as error:
        print(f"model-agent: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
