"""Safely ingest nono outbox files and construct exact EMILIA actions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from jsonschema import Draft202012Validator

from controller.emilia_adapter import receipt_required_challenge

MAX_REQUEST_BYTES: Final = 64 * 1024
MAX_MATERIAL_BYTES: Final = 1024 * 1024 * 1024
CHUNK_BYTES: Final = 1024 * 1024
REQUEST_NAME_PATTERN: Final = re.compile(
    r"^(?P<id>[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\.json$"
)


class OutboxError(Exception):
    """An outbox request failed closed."""


@dataclass(frozen=True, slots=True)
class ControllerPolicy:
    artifact: Path
    input_root: Path
    allowed_targets: frozenset[str]
    policy_version: str


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise OutboxError("request contains duplicate JSON members")
        value[key] = item
    return value


def _read_regular(path: Path, maximum: int) -> bytes:
    # O_NONBLOCK is security-significant here.  The outbox is writable by the
    # untrusted process, so it can contain a FIFO.  Opening that FIFO for read
    # without O_NONBLOCK would freeze the controller before fstat can reject it.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OutboxError("could not safely open material") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
            raise OutboxError("material is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
            if not chunk:
                raise OutboxError("material became shorter while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OutboxError("material grew while reading")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise OutboxError("material changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _atomic_write_exclusive(path: Path, encoded: bytes) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OutboxError("controller write did not make progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise OutboxError("could not persist controller record") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _strict_request(encoded: bytes, schema: dict[str, object]) -> dict[str, str]:
    def reject_constant(value: str) -> None:
        raise OutboxError(f"invalid JSON constant: {value}")

    try:
        request = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OutboxError("request is not strict UTF-8 JSON") from error
    errors = sorted(
        Draft202012Validator(schema).iter_errors(request),
        key=lambda error: tuple(str(component) for component in error.absolute_path),
    )
    if errors:
        raise OutboxError("request does not match the closed schema")
    if not isinstance(request, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in request.items()
    ):
        raise OutboxError("request contains an unsupported value")
    return request


def _sha256_regular(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OutboxError("could not safely open artifact") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > MAX_MATERIAL_BYTES
        ):
            raise OutboxError("artifact is not a bounded regular file")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
            if not chunk:
                raise OutboxError("artifact became shorter while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OutboxError("artifact grew while hashing")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise OutboxError("artifact changed while hashing")
        return f"sha256:{digest.hexdigest()}"
    finally:
        os.close(descriptor)


def _input_digest(root: Path, name: str) -> str:
    if Path(name).name != name or name in (".", ".."):
        raise OutboxError("input name is not a single safe path component")
    resolved_root = root.resolve(strict=True)
    root_descriptor = os.open(resolved_root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(name, flags, dir_fd=root_descriptor)
        except OSError as error:
            raise OutboxError("input cannot be opened beneath the trusted root") from error
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_MATERIAL_BYTES:
                raise OutboxError("input is not a bounded regular file")
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
                if not chunk:
                    raise OutboxError("input became shorter while hashing")
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise OutboxError("input grew while hashing")
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise OutboxError("input changed while hashing")
            return f"sha256:{digest.hexdigest()}"
        finally:
            os.close(descriptor)
    finally:
        os.close(root_descriptor)


def build_action(request: dict[str, str], policy: ControllerPolicy) -> dict[str, str]:
    if request["target"] not in policy.allowed_targets:
        raise OutboxError("target is not allowlisted by controller policy")
    input_sha256 = _input_digest(policy.input_root, request["input_name"])
    if input_sha256 != request["expected_input_sha256"]:
        raise OutboxError("input digest does not match the request")
    return {
        "action_type": "workload.execute",
        "operation": request["operation"],
        "target": request["target"],
        "artifact_sha256": _sha256_regular(policy.artifact.resolve(strict=True)),
        "input_sha256": input_sha256,
        "occurrence_id": str(uuid.uuid4()),
        "policy_version": policy.policy_version,
    }


def process_request(
    source: Path,
    *,
    schema: dict[str, object],
    storage: Path,
    inbox: Path,
    policy: ControllerPolicy,
) -> dict[str, object]:
    match = REQUEST_NAME_PATTERN.fullmatch(source.name)
    if match is None:
        raise OutboxError("outbox filename is invalid")
    request_id = match.group("id")
    encoded = _read_regular(source, MAX_REQUEST_BYTES)
    stored_request = storage / f"{request_id}.request.json"
    _atomic_write_exclusive(stored_request, encoded)
    try:
        source.unlink()
    except OSError as error:
        raise OutboxError("could not retire ingested outbox file") from error
    request = _strict_request(encoded, schema)
    if request["request_id"] != request_id:
        raise OutboxError("request identifier does not match its filename")
    action = build_action(request, policy)
    action_encoded = json.dumps(
        action,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    _atomic_write_exclusive(storage / f"{request_id}.action.json", action_encoded)
    status = {
        "request_id": request_id,
        "state": "RECEIPT_REQUIRED",
        "challenge": receipt_required_challenge(action),
    }
    status_encoded = json.dumps(
        status,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    _atomic_write_exclusive(inbox / f"{request_id}.status.json", status_encoded)
    return status


def _load_schema(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(value)
    except (OSError, json.JSONDecodeError, TypeError) as error:
        raise OutboxError("request schema is unavailable or invalid") from error
    if not isinstance(value, dict):
        raise OutboxError("request schema is not an object")
    return value


def run_once(
    *,
    outbox: Path,
    schema: dict[str, object],
    storage: Path,
    inbox: Path,
    policy: ControllerPolicy,
) -> tuple[dict[str, object], ...]:
    results: list[dict[str, object]] = []
    sources: Iterable[Path] = sorted(outbox.iterdir(), key=lambda item: item.name)
    for source in sources:
        if not source.name.endswith(".json"):
            continue
        try:
            results.append(
                process_request(
                    source,
                    schema=schema,
                    storage=storage,
                    inbox=inbox,
                    policy=policy,
                )
            )
        except OutboxError:
            match = REQUEST_NAME_PATTERN.fullmatch(source.name)
            try:
                source.unlink(missing_ok=True)
            except OSError:
                pass
            if match is None:
                results.append({"state": "DENIED", "reason": "invalid_filename"})
                continue
            request_id = match.group("id")
            denial = {
                "request_id": request_id,
                "state": "DENIED",
                "reason": "request_rejected",
            }
            denial_encoded = json.dumps(
                denial,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            try:
                _atomic_write_exclusive(
                    inbox / f"{request_id}.status.json",
                    denial_encoded,
                )
            except OutboxError:
                pass
            results.append(denial)
    return tuple(results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="outbox-watcher")
    parser.add_argument("--outbox", type=Path, required=True)
    parser.add_argument("--inbox", type=Path, required=True)
    parser.add_argument("--storage", type=Path, required=True)
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--allowed-target", action="append", required=True)
    parser.add_argument("--policy-version", required=True)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "request_schema.json",
    )
    args = parser.parse_args(argv)
    try:
        for directory in (args.outbox, args.inbox, args.storage, args.input_root):
            if not directory.resolve(strict=True).is_dir():
                raise OutboxError("configured directory is invalid")
        policy = ControllerPolicy(
            artifact=args.artifact,
            input_root=args.input_root,
            allowed_targets=frozenset(args.allowed_target),
            policy_version=args.policy_version,
        )
        results = run_once(
            outbox=args.outbox,
            schema=_load_schema(args.schema),
            storage=args.storage,
            inbox=args.inbox,
            policy=policy,
        )
    except (OSError, OutboxError) as error:
        print(f"outbox-watcher: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"processed": len(results)}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
