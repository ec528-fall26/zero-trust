"""Generate the nono profile for the file-based EMILIA handoff."""

from __future__ import annotations

import argparse
import json
import os
import re
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


MODEL_ROUTE = "ec528_model"
MODEL_UPSTREAM = "https://api.anthropic.com"
MODEL_PHANTOM_VAR = "EC528_MODEL_PHANTOM"
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _model_network(credential_env: str) -> dict[str, object]:
    """Proxy-only networking: the agent reaches api.anthropic.com only through
    nono's credential proxy, which runs outside the sandbox, reads the real key
    from the supervisor's environment, and gives the agent a phantom token."""
    if not _ENV_NAME.fullmatch(credential_env):
        raise RequestSubmissionError("model credential variable name is invalid")
    return {
        "credentials": [MODEL_ROUTE],
        "custom_credentials": {
            MODEL_ROUTE: {
                "upstream": MODEL_UPSTREAM,
                "credential_key": f"env://{credential_env}",
                "env_var": MODEL_PHANTOM_VAR,
                "inject_header": "x-api-key",
                "credential_format": "{}",
            },
        },
    }


def _claude_code_network(token_env: str) -> dict[str, object]:
    """Claude Code on a Claude subscription.  The real token (from
    `claude setup-token`, scope user:inference) stays in the supervisor; the
    proxy injects it as a bearer header and the agent sees a phantom value in
    CLAUDE_CODE_OAUTH_TOKEN and a loopback ANTHROPIC_BASE_URL."""
    if not _ENV_NAME.fullmatch(token_env):
        raise RequestSubmissionError("Claude Code token variable name is invalid")
    return {
        "credentials": ["anthropic"],
        "custom_credentials": {
            "anthropic": {
                "upstream": MODEL_UPSTREAM,
                "credential_key": f"env://{token_env}",
                "env_var": "CLAUDE_CODE_OAUTH_TOKEN",
                "inject_header": "Authorization",
                "credential_format": "Bearer {}",
            },
        },
    }


def build_profile(
    *,
    outbox: Path,
    inbox: Path,
    model_credential_env: str | None = None,
    claude_code_token_env: str | None = None,
    agent_read: list[Path] | None = None,
) -> dict[str, object]:
    canonical_outbox = _canonical_directory(outbox, "outbox")
    canonical_inbox = _canonical_directory(inbox, "inbox")
    if _contains(canonical_outbox, canonical_inbox) or _contains(
        canonical_inbox, canonical_outbox
    ):
        raise RequestSubmissionError("outbox and inbox must not overlap")
    if canonical_outbox.stat().st_dev != canonical_inbox.stat().st_dev:
        raise RequestSubmissionError("outbox and inbox must be on the same trusted host")
    if model_credential_env is not None and claude_code_token_env is not None:
        raise RequestSubmissionError("choose one model route")
    claude_code = claude_code_token_env is not None
    model = model_credential_env is not None or claude_code
    allow_vars = ["HOME", "LANG", "LC_*", "PATH", "TERM", "TMPDIR"]
    deny_vars = [
        "*CREDENTIAL*",
        "*KEY*",
        "*PASSWORD*",
        "*SECRET*",
        "*TOKEN*",
        "AZURE_*",
        "EMILIA_*",
        "KEYLIME_*",
    ]
    if model_credential_env is not None:
        allow_vars += ["EC528_MODEL_*", "*_BASE_URL"]
        network = _model_network(model_credential_env)
    elif claude_code:
        # The phantom lives in CLAUDE_CODE_OAUTH_TOKEN, so *TOKEN* cannot be a
        # blanket deny here; the variable holding the real token is denied by
        # name, and only allow-listed variables reach the agent at all.
        allow_vars += [
            "CLAUDE_CODE_OAUTH_TOKEN",
            "ANTHROPIC_BASE_URL",
            "CLAUDE_CONFIG_DIR",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
            "DISABLE_AUTOUPDATER",
        ]
        deny_vars = [name for name in deny_vars if name != "*TOKEN*"] + [
            claude_code_token_env,
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "AWS_*",
        ]
        network = _claude_code_network(claude_code_token_env)
    else:
        network = {"block": True}
    readable = [os.fspath(canonical_inbox)]
    for path in agent_read or []:
        # Read-only access for the agent's own program files (e.g. the
        # Claude Code binary); never the controller's directories.
        resolved = _canonical_directory(path, "agent read")
        if _contains(resolved, canonical_outbox) or _contains(resolved, canonical_inbox):
            raise RequestSubmissionError("agent read path must not contain the handoff")
        readable.append(os.fspath(resolved))
    return {
        "meta": {
            "name": "ec528-nono-emilia-handoff",
            "version": "0.2.0" if model else "0.1.0",
            "description": (
                "Agent with a one-way EMILIA request outbox and proxy-only access to the model API"
                if model
                else "Networkless agent with a one-way EMILIA request outbox"
            ),
        },
        "groups": {
            "include": ["deny_credentials"],
        },
        "workdir": {
            "access": "readwrite",
        },
        "filesystem": {
            "write": [os.fspath(canonical_outbox)],
            "read": readable,
        },
        "network": network,
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
            "allow_vars": allow_vars,
            "deny_vars": deny_vars,
            "case_insensitive_vars": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nono-handoff-profile")
    parser.add_argument("--outbox", type=Path, required=True)
    parser.add_argument("--inbox", type=Path, required=True)
    parser.add_argument(
        "--model-credential-env",
        help="name of the supervisor environment variable holding the Anthropic API key",
    )
    parser.add_argument(
        "--claude-code-token-env",
        help="name of the supervisor environment variable holding a `claude setup-token` token",
    )
    parser.add_argument(
        "--agent-read",
        type=Path,
        action="append",
        default=[],
        help="read-only directory the agent program needs (repeatable)",
    )
    args = parser.parse_args(argv)
    try:
        profile = build_profile(
            outbox=args.outbox,
            inbox=args.inbox,
            model_credential_env=args.model_credential_env,
            claude_code_token_env=args.claude_code_token_env,
            agent_read=args.agent_read,
        )
    except RequestSubmissionError as error:
        print(f"nono-handoff-profile: {error}", file=sys.stderr)
        return 1
    print(json.dumps(profile, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
