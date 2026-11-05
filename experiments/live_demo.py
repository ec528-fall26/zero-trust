#!/usr/bin/env python3
"""Prepare the Nono handoff and launch the local integration dashboard."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
import webbrowser
from pathlib import Path

from agent_tool.submit_request import build_request, load_schema, publish_request
from controller.outbox_watcher import ControllerPolicy, process_request


def available_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("127.0.0.1", preferred))
        except OSError:
            listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def prepare(repository: Path) -> dict[str, Path]:
    build_root = repository / "build"
    build_root.mkdir(mode=0o700, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="live-demo-", dir=build_root))
    directories = {
        name: root / name for name in ("outbox", "inbox", "storage", "inputs", "state")
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)

    # Same bytes as the workload and input installed on the AWS node, so the
    # dashboard works against the real Keylime MCP as well as the local stand-in.
    workload = repository / "infra" / "aws" / "workload"
    input_path = directories["inputs"] / "demo-payload.txt"
    input_path.write_bytes((workload / "demo-payload.txt").read_bytes())
    artifact_path = workload / "checksum.sh"
    input_digest = f"sha256:{hashlib.sha256(input_path.read_bytes()).hexdigest()}"
    request_id = str(uuid.uuid4())
    schema = load_schema(repository / "src" / "request_schema.json")
    request = build_request(
        operation="checksum.sha256",
        target="aws-keylime-demo-01",
        input_name=input_path.name,
        expected_input_sha256=input_digest,
        request_id=request_id,
    )
    source = publish_request(request, schema=schema, outbox=directories["outbox"])
    process_request(
        source,
        schema=schema,
        storage=directories["storage"],
        inbox=directories["inbox"],
        policy=ControllerPolicy(
            artifact=artifact_path,
            input_root=directories["inputs"],
            allowed_targets=frozenset({"aws-keylime-demo-01"}),
            policy_version="demo-2.1",
        ),
    )
    return {
        "root": root,
        "action": directories["storage"] / f"{request_id}.action.json",
        "artifact": artifact_path,
        "input": input_path,
        "state": directories["state"],
    }


def run_confinement(repository: Path, nono_binary: str) -> dict[str, object]:
    environment = {**os.environ, "PYTHONPATH": os.fspath(repository / "src")}
    completed = subprocess.run(
        [
            sys.executable,
            os.fspath(repository / "experiments" / "nono_handoff_confinement.py"),
            "--nono-binary",
            nono_binary,
        ],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Nono confinement checks failed")
    result = json.loads(completed.stdout)
    if result.get("passed") is not True:
        raise RuntimeError("Nono confinement checks did not pass")
    return result


def wait_until_ready(url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("demo server exited before becoming ready")
        try:
            with urllib.request.urlopen(f"{url}/api/state", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("demo server did not become ready")


def main() -> int:
    parser = argparse.ArgumentParser(prog="live-demo")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--nono-binary", default=shutil.which("nono") or "nono")
    parser.add_argument("--skip-confinement", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]

    if not args.skip_confinement:
        result = run_confinement(repository, args.nono_binary)
        print(f"Nono confinement: PASS ({len(result['results'])} checks)")

    prepared = prepare(repository)
    port = available_port(args.port)
    url = f"http://127.0.0.1:{port}"
    command = [
        "node",
        os.fspath(repository / "src" / "demo" / "demo_server.mjs"),
        "--action",
        os.fspath(prepared["action"]),
        "--artifact",
        os.fspath(prepared["artifact"]),
        "--input",
        os.fspath(prepared["input"]),
        "--state-dir",
        os.fspath(prepared["state"]),
        "--port",
        str(port),
    ]
    process = subprocess.Popen(command, cwd=repository)
    try:
        wait_until_ready(url, process)
        print(f"Live demo: {url}")
        print(f"Evidence directory: {prepared['root']}")
        if not args.no_browser:
            webbrowser.open(url)
        return process.wait()
    except KeyboardInterrupt:
        return 0
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
