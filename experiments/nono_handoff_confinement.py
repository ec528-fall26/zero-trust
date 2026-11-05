#!/usr/bin/env python3
"""Black-box checks for the one-way nono outbox/inbox boundary."""

from __future__ import annotations

import argparse
import http.server
import json
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

from agent_tool.nono_profile import build_profile


def run_case(base: list[str], command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*base, *command],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - name is fixed by BaseHTTPRequestHandler
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"unprotected executor reached")

    def log_message(self, _format: str, *args: object) -> None:
        del args


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nono-binary", default="nono")
    args = parser.parse_args()
    resolved = shutil.which(args.nono_binary)
    if resolved is None:
        parser.error(f"nono binary was not found: {args.nono_binary}")

    repository = Path(__file__).resolve().parents[1]
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="nono-handoff-", dir=repository) as temporary:
        root = Path(temporary)
        outbox = root / "outbox"
        inbox = root / "inbox"
        work = root / "work"
        for directory in (outbox, inbox, work):
            directory.mkdir(mode=0o700)
        private = root / "controller-private"
        receipt_store = private / "receipt-store"
        receipt_store.mkdir(parents=True, mode=0o700)
        sensitive_files = {
            "receipt_store_read_blocked": receipt_store / "state.json",
            "signer_key_read_blocked": private / "signer.key",
            "mcp_token_read_blocked": private / "keylime-mcp-token",
        }
        for sensitive_file in sensitive_files.values():
            sensitive_file.write_text("controller secret", encoding="ascii")
            sensitive_file.chmod(0o600)
        status_file = inbox / "request.status.json"
        status_file.write_text('{"state":"PENDING_APPROVAL"}', encoding="ascii")
        profile_path = root / "profile.json"
        profile_path.write_text(
            json.dumps(build_profile(outbox=outbox, inbox=inbox)),
            encoding="utf-8",
        )
        base = [
            str(Path(resolved).resolve(strict=True)),
            "run",
            "--silent",
            "--profile",
            str(profile_path),
            "--workdir",
            str(work),
            "--allow-cwd",
            "--strict-broker-path",
            "--audit-integrity",
            "--",
        ]

        request_file = outbox / "request.json"
        write_outbox = run_case(
            base,
            ["/bin/sh", "-c", f"printf request > '{request_file}'"],
        )
        results.append(
            {
                "case": "outbox_write_allowed",
                "passed": write_outbox.returncode == 0 and request_file.exists(),
                "returncode": write_outbox.returncode,
            }
        )
        read_outbox = run_case(base, ["/bin/cat", str(request_file)])
        results.append(
            {
                "case": "outbox_read_blocked",
                "passed": read_outbox.returncode != 0,
                "returncode": read_outbox.returncode,
            }
        )
        read_inbox = run_case(base, ["/bin/cat", str(status_file)])
        results.append(
            {
                "case": "inbox_read_allowed",
                "passed": read_inbox.returncode == 0 and b"PENDING_APPROVAL" in read_inbox.stdout,
                "returncode": read_inbox.returncode,
            }
        )
        forbidden_status = inbox / "forged.status.json"
        write_inbox = run_case(
            base,
            ["/bin/sh", "-c", f"printf forged > '{forbidden_status}'"],
        )
        results.append(
            {
                "case": "inbox_write_blocked",
                "passed": write_inbox.returncode != 0 and not forbidden_status.exists(),
                "returncode": write_inbox.returncode,
            }
        )
        network = run_case(
            base,
            ["/usr/bin/curl", "--silent", "--max-time", "2", "https://example.com/"],
        )
        results.append(
            {
                "case": "network_blocked",
                "passed": network.returncode != 0,
                "returncode": network.returncode,
            }
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            direct_bypass = run_case(
                base,
                [
                    "/usr/bin/curl",
                    "--silent",
                    "--max-time",
                    "2",
                    f"http://127.0.0.1:{server.server_port}/mcp",
                ],
            )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)
        results.append(
            {
                "case": "direct_mcp_bypass_blocked",
                "passed": direct_bypass.returncode != 0,
                "returncode": direct_bypass.returncode,
            }
        )
        for case_name, sensitive_file in sensitive_files.items():
            attempted_read = run_case(base, ["/bin/cat", str(sensitive_file)])
            results.append(
                {
                    "case": case_name,
                    "passed": attempted_read.returncode != 0,
                    "returncode": attempted_read.returncode,
                }
            )

    passed = all(bool(result["passed"]) for result in results)
    print(
        json.dumps(
            {
                "schema": "ec528.nono-emilia.confinement.v1",
                "passed": passed,
                "results": results,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
