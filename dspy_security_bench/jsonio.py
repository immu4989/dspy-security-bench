"""Bounded, unambiguous JSON intake for local evidence files."""

from __future__ import annotations

import base64
import json
import math
from pathlib import Path
from typing import Any

MAX_JSON_DEPTH = 100
MAX_SIGNED_STATEMENT_BYTES = 1_000_000


def read_json_object(path: Path, maximum: int) -> dict[str, Any]:
    """Read at most the allowed bytes and reject parser-dependent JSON values.

    Diagnostics intentionally exclude source keys and values, which may contain
    private identifiers. This reader does not authenticate or validate a schema.
    """
    if type(maximum) is not int or maximum < 1:
        raise ValueError("maximum JSON input size must be a positive integer")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    return decode_json_object(raw, maximum)


def decode_base64_statement(value: object) -> tuple[bytes, dict[str, Any]]:
    """Decode a bounded DSSE JSON object; this does not verify its signature."""
    limit = MAX_SIGNED_STATEMENT_BYTES
    if not isinstance(value, str) or len(value) > 4 * ((limit + 2) // 3):
        raise ValueError("signed statement must be bounded base64 text")
    raw = base64.b64decode(value, validate=True)
    return raw, decode_json_object(raw, limit)


def decode_json_object(raw: bytes, maximum: int) -> dict[str, Any]:
    """Parse bounded UTF-8 bytes with the same rules as local evidence files."""
    if not isinstance(raw, bytes) or type(maximum) is not int or maximum < 1:
        raise ValueError("JSON input must be bytes with a positive integer size limit")
    if len(raw) > maximum:
        raise ValueError(f"input exceeds {maximum} bytes")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("JSON input must be UTF-8") from exc
    try:
        payload = json.loads(
            source, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except RecursionError as exc:
        raise ValueError("JSON input nesting exceeds the supported limit") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON at line {exc.lineno}, column {exc.colno}") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    pending = [(payload, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"JSON input nesting exceeds {MAX_JSON_DEPTH}")
        if isinstance(item, dict):
            pending.extend((key, depth + 1) for key in item)
            pending.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            pending.extend((value, depth + 1) for value in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("JSON numbers must be finite")
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("JSON strings must contain valid Unicode scalar values") from exc
    return payload


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON object contains duplicate member names")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("JSON numbers must be finite")
