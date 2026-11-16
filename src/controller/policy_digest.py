"""Derive ``policy_version`` from the policies themselves.

Mirror of ``src/keylime_mcp/policy_digest.mjs``.  Both implementations are
checked against the same test vector (see ``tests/test_policy_digest.py`` and
``tests-js/policy_digest.test.mjs``), so a digest computed by the watcher equals
the one computed by the gate and by the node.

``policy_version`` = ``pd1-`` + the first 60 hex characters of
``sha256(canonical JSON of {"@version": "EC528-POLICY-DIGEST-v1",
"keylime_policy_sha256": ..., "approval_policy": ...})``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

POLICY_DIGEST_VERSION: Final = "EC528-POLICY-DIGEST-v1"
PREFIX: Final = "pd1-"
HEX_CHARACTERS: Final = 60
MAXIMUM_DEPTH: Final = 16
MAXIMUM_POLICY_BYTES: Final = 1024 * 1024
DIGEST_PATTERN: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
KEY_PATTERN: Final = re.compile(r"^[\x20-\x7e]*$")


class PolicyDigestError(Exception):
    """A policy could not be turned into a digest."""


def _check(value: Any, depth: int = 0) -> None:
    if depth > MAXIMUM_DEPTH:
        raise PolicyDigestError("policy is too deep")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise PolicyDigestError("policy number is unsupported")
        return
    if isinstance(value, list):
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or KEY_PATTERN.fullmatch(key) is None:
                raise PolicyDigestError("policy key is unsupported")
            _check(item, depth + 1)
        return
    raise PolicyDigestError("policy value is unsupported")


def canonical_policy_json(value: Any) -> str:
    """Deterministic JSON: sorted ASCII keys, integers only, no whitespace."""
    _check(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def policy_digest(*, keylime_policy_sha256: str, approval_policy: Mapping[str, Any]) -> str:
    if DIGEST_PATTERN.fullmatch(keylime_policy_sha256) is None:
        raise PolicyDigestError("keylime_policy_sha256 must be a sha256: digest")
    if not isinstance(approval_policy, Mapping):
        raise PolicyDigestError("approval_policy must be an object")
    document = canonical_policy_json(
        {
            "@version": POLICY_DIGEST_VERSION,
            "keylime_policy_sha256": keylime_policy_sha256,
            "approval_policy": dict(approval_policy),
        }
    )
    return PREFIX + hashlib.sha256(document.encode("utf-8")).hexdigest()[:HEX_CHARACTERS]


def _read_bounded(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise PolicyDigestError("could not read a policy file") from error
    if not data or len(data) > MAXIMUM_POLICY_BYTES:
        raise PolicyDigestError("policy file is empty or too large")
    return data


def policy_version_from_files(*, keylime_policy: Path, approval_policy: Path) -> str:
    keylime_bytes = _read_bounded(keylime_policy)
    approval_bytes = _read_bounded(approval_policy)
    try:
        approval = json.loads(approval_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise PolicyDigestError("approval policy file is not valid JSON") from error
    if not isinstance(approval, dict):
        raise PolicyDigestError("approval policy file must hold a JSON object")
    return policy_digest(
        keylime_policy_sha256=sha256_digest(keylime_bytes),
        approval_policy=approval,
    )
