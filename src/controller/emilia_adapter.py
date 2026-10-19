"""Build the exact EMILIA Receipt-Required challenge for a trusted action."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Final

ACTION_TYPE: Final = "workload.execute"
MANIFEST_URL: Final = "/.well-known/agent-actions.json"
REQUIRED_FIELDS: Final = (
    "action_type",
    "operation",
    "target",
    "artifact_sha256",
    "input_sha256",
    "occurrence_id",
    "policy_version",
)
DIGEST_PATTERN: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
TARGET_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
UUID_PATTERN: Final = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
)
POLICY_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class EmiliaAdapterError(Exception):
    """The trusted action cannot be mapped into the pinned EMILIA profile."""


def canonical_action_bytes(action: Mapping[str, object]) -> bytes:
    if set(action) != set(REQUIRED_FIELDS):
        raise EmiliaAdapterError("action fields do not match the pinned profile")
    if action.get("action_type") != ACTION_TYPE:
        raise EmiliaAdapterError("action type does not match the pinned profile")
    for field in REQUIRED_FIELDS:
        value = action[field]
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
            raise EmiliaAdapterError(f"action field is invalid: {field}")
    for field in ("artifact_sha256", "input_sha256"):
        if DIGEST_PATTERN.fullmatch(str(action[field])) is None:
            raise EmiliaAdapterError(f"action digest is invalid: {field}")
    if action["operation"] != "checksum.sha256":
        raise EmiliaAdapterError("action operation is invalid")
    if TARGET_PATTERN.fullmatch(str(action["target"])) is None:
        raise EmiliaAdapterError("action target is invalid")
    if UUID_PATTERN.fullmatch(str(action["occurrence_id"])) is None:
        raise EmiliaAdapterError("action occurrence identifier is invalid")
    if POLICY_PATTERN.fullmatch(str(action["policy_version"])) is None:
        raise EmiliaAdapterError("action policy version is invalid")
    try:
        encoded = json.dumps(
            dict(action),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise EmiliaAdapterError("action is outside the canonical JSON profile") from error
    return encoded


def action_hash(action: Mapping[str, object]) -> str:
    return f"sha256:{hashlib.sha256(canonical_action_bytes(action)).hexdigest()}"


def receipt_required_challenge(action: Mapping[str, object]) -> dict[str, object]:
    observed_hash = action_hash(action)
    return {
        "status": 428,
        "title": "EMILIA Receipt Required",
        "required": {
            "action": ACTION_TYPE,
            "action_hash": observed_hash,
            "assurance_class": "quorum",
            "manifest": MANIFEST_URL,
            "max_age_sec": 900,
            "profile": "EP-RECEIPT-v1",
            "proof_header": "X-EMILIA-Receipt",
            "quorum": {
                "distinct_humans": True,
                "m": 2,
                "mode": "m_of_n",
                "required": True,
            },
            "required_fields": list(REQUIRED_FIELDS),
        },
    }
