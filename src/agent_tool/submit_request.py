"""Create one strictly validated request in the nono outbox."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Final

from jsonschema import Draft202012Validator

SCHEMA_VERSION: Final = "ec528.nono.request.v1"
MAX_REQUEST_BYTES: Final = 64 * 1024


class RequestSubmissionError(Exception):
    """A request could not be safely validated or published."""


def load_schema(schema_path: Path) -> dict[str, object]:
    try:
        raw = schema_path.read_bytes()
        schema = json.loads(raw.decode("utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
        raise RequestSubmissionError("request schema is unavailable or invalid") from error
    if not isinstance(schema, dict):
        raise RequestSubmissionError("request schema must be an object")
    return schema


def build_request(
    *,
    operation: str,
    target: str,
    input_name: str,
    expected_input_sha256: str,
    request_id: str | None = None,
) -> dict[str, str]:
    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id or str(uuid.uuid4()),
        "operation": operation,
        "target": target,
        "input_name": input_name,
        "expected_input_sha256": expected_input_sha256,
    }


def validate_request(request: object, schema: dict[str, object]) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(request),
        key=lambda error: tuple(str(component) for component in error.absolute_path),
    )
    if errors:
        raise RequestSubmissionError(f"request validation failed: {errors[0].message}")


def _write_all(descriptor: int, encoded: bytes) -> None:
    remaining = memoryview(encoded)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise RequestSubmissionError("request write did not make progress")
        remaining = remaining[written:]


def publish_request(
    request: dict[str, str],
    *,
    schema: dict[str, object],
    outbox: Path,
) -> Path:
    validate_request(request, schema)
    encoded = json.dumps(
        request,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(encoded) > MAX_REQUEST_BYTES:
        raise RequestSubmissionError("request exceeds the size limit")

    resolved_outbox = outbox.resolve(strict=True)
    if not resolved_outbox.is_dir():
        raise RequestSubmissionError("outbox is not a directory")
    request_id = request["request_id"]
    temporary = resolved_outbox / f".{request_id}.{uuid.uuid4().hex}.tmp"
    destination = resolved_outbox / f"{request_id}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, destination, follow_symlinks=False)
        os.unlink(temporary)
        directory_descriptor = os.open(resolved_outbox, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise RequestSubmissionError("could not atomically publish request") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="submit-request")
    parser.add_argument("--outbox", type=Path, required=True)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "request_schema.json",
    )
    parser.add_argument("--operation", default="checksum.sha256")
    parser.add_argument("--target", required=True)
    parser.add_argument("--input-name", required=True)
    parser.add_argument("--expected-input-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        schema = load_schema(args.schema)
        request = build_request(
            operation=args.operation,
            target=args.target,
            input_name=args.input_name,
            expected_input_sha256=args.expected_input_sha256,
        )
        destination = publish_request(request, schema=schema, outbox=args.outbox)
    except RequestSubmissionError as error:
        print(f"submit-request: {error}", file=sys.stderr)
        return 1
    print(destination.stem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
