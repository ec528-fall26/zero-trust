"""Generate the nono profile for the file-based EMILIA handoff."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from agent_tool.submit_request import RequestSubmissionError


def _canonical_directory(path: Path, field: str) -> Path:
    try:
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise RequestSubmissionError(f"{field} directory is unavailable") from error
    if not canonical.is_dir():
        raise RequestSubmissionError(f"{field} is not a directory")
    return canonical


def _contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def build_profile(*, outbox: Path, inbox: Path) -> dict[str, object]:
    canonical_outbox = _canonical_directory(outbox, "outbox")
    canonical_inbox = _canonical_directory(inbox, "inbox")
    if _contains(canonical_outbox, canonical_inbox) or _contains(
        canonical_inbox, canonical_outbox
    ):
        raise RequestSubmissionError("outbox and inbox must not overlap")
    if canonical_outbox.stat().st_dev != canonical_inbox.stat().st_dev:
        raise RequestSubmissionError("outbox and inbox must be on the same trusted host")
    return {
        "meta": {
            "name": "ec528-nono-emilia-handoff",
            "version": "0.1.0",
            "description": "Networkless agent with a one-way EMILIA request outbox",
        },
        "groups": {
            "include": ["deny_credentials"],
        },
        "workdir": {
            "access": "readwrite",
        },
        "filesystem": {
            "write": [os.fspath(canonical_outbox)],
            "read": [os.fspath(canonical_inbox)],
        },
        "network": {
            "block": True,
        },
        "security": {
            "signal_mode": "isolated",
            "process_info_mode": "isolated",
            "capability_elevation": False,
            "wsl2_proxy_policy": "error",
        },
        "linux": {
            "af_unix_mediation": "pathname",
            "sandbox_policy": "auto",
        },
        "environment": {
            "allow_vars": ["HOME", "LANG", "LC_*", "PATH", "TERM", "TMPDIR"],
            "deny_vars": [
                "*CREDENTIAL*",
                "*KEY*",
                "*PASSWORD*",
                "*SECRET*",
                "*TOKEN*",
                "AZURE_*",
                "EMILIA_*",
                "KEYLIME_*",
            ],
            "case_insensitive_vars": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nono-handoff-profile")
    parser.add_argument("--outbox", type=Path, required=True)
    parser.add_argument("--inbox", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        profile = build_profile(outbox=args.outbox, inbox=args.inbox)
    except RequestSubmissionError as error:
        print(f"nono-handoff-profile: {error}", file=sys.stderr)
        return 1
    print(json.dumps(profile, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
