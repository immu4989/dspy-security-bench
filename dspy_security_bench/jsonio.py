"""Bounded, unambiguous JSON intake for local evidence files."""

from __future__ import annotations

import base64
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

MAX_JSON_DEPTH = 100
MAX_SIGNED_STATEMENT_BYTES = 1_000_000
MAX_NUMBER_CHARACTERS = 128


def read_json_object(path: Path, maximum: int) -> dict[str, Any]:
    """Read at most the allowed bytes and reject parser-dependent JSON values.

    Diagnostics intentionally exclude source keys and values, which may contain
    private identifiers. This reader does not authenticate or validate a schema.
    """
    return read_json_snapshot(path, maximum)[1]


def read_json_snapshot(path: Path, maximum: int) -> tuple[bytes, dict[str, Any]]:
    """Return the exact bounded bytes and their strict interpretation from one read."""
    raw = read_regular_bytes(path, maximum)
    return raw, decode_json_object(raw, maximum)


def read_regular_bytes(path: Path, maximum: int) -> bytes:
    """Read at most maximum + 1 bytes from an ordinary non-symlink final component.

    The extra byte is an overflow probe; callers must reject overflow before
    decoding or using the data. Nonblocking open prevents POSIX FIFO replacement
    from waiting for a writer. Descriptor checks precede reading. This does not
    confine ancestors, reject hard links, freeze concurrent in-place writes, or
    bound filesystem latency; use stable owner-controlled local inputs.
    """
    if type(maximum) is not int or maximum < 1:
        raise ValueError("maximum input size must be a positive integer")

    def ordinary(info):
        return (stat.S_ISREG(info.st_mode)
                and not getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))

    try:
        path = Path(path)
        before = path.lstat()
        if not ordinary(before):
            raise ValueError("input must be a regular non-symlink file")
        flags = os.O_RDONLY
        for flag in ("O_BINARY", "O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
            flags |= getattr(os, flag, 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not ordinary(opened):
                raise ValueError("opened input is not a regular file")
            # Some platforms do not expose useful inode IDs. Where available,
            # reject an observed replacement between metadata check and open.
            if (before.st_ino and opened.st_ino
                    and (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
                raise ValueError("input changed while opening; retry with stable local evidence")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                return stream.read(maximum + 1)
        finally:
            os.close(descriptor)
    except (OSError, TypeError):
        raise ValueError("could not read ordinary local evidence; filesystem details withheld") from None


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
            source, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
            parse_int=_bounded_int, parse_float=_bounded_float,
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


def _bounded_int(value: str) -> int:
    if len(value) > MAX_NUMBER_CHARACTERS:
        raise ValueError(f"JSON numeric tokens must not exceed {MAX_NUMBER_CHARACTERS} characters")
    return int(value)


def _bounded_float(value: str) -> float:
    if len(value) > MAX_NUMBER_CHARACTERS:
        raise ValueError(f"JSON numeric tokens must not exceed {MAX_NUMBER_CHARACTERS} characters")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("JSON numbers must be finite")
    return result
