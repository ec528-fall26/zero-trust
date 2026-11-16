"""Load the repository's single, versioned security-parameter policy."""

from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType
from typing import Final, Mapping

_POLICY_PATH: Final = Path(__file__).resolve().parents[1] / "config" / "security-parameters.json"
_BOUNDS: Final = {
    "receipt_max_age_sec": (1, 86_400),
    "approval_window_sec": (1, 86_400),
    "attestation_max_age_sec": (1, 86_400),
    "clock_skew_tolerance_sec": (0, 300),
    "fresh_attestation_timeout_sec": (1, 120),
    "revocation_list_max_age_sec": (1, 86_400),
}


def _load() -> Mapping[str, int]:
    try:
        value = json.loads(_POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("security parameter policy is unavailable") from error
    if not isinstance(value, dict) or set(value) != set(_BOUNDS):
        raise RuntimeError("security parameter policy fields are invalid")
    for name, (minimum, maximum) in _BOUNDS.items():
        setting = value[name]
        if (
            not isinstance(setting, int)
            or isinstance(setting, bool)
            or setting < minimum
            or setting > maximum
        ):
            raise RuntimeError(f"security parameter is invalid: {name}")
    if value["receipt_max_age_sec"] > value["approval_window_sec"]:
        raise RuntimeError("receipt lifetime must not exceed the approval window")
    return MappingProxyType(value)


SECURITY_PARAMETERS: Final = _load()
