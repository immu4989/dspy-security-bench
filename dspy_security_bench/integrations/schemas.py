"""Detached, offline argument validation for schema-aware native bridges."""

from __future__ import annotations

import json
import math
from copy import deepcopy

from dspy_security_bench.jsonio import MAX_JSON_DEPTH, decode_json_object

MAX_TOOL_JSON_BYTES = 1_000_000
MAX_TOOL_JSON_NODES = 100_000


class NativeToolSchemaError(ValueError):
    """A supplied tool schema cannot be used; not a model argument mistake."""


class _ToolArgumentsError(ValueError):
    """Arguments failed admission before the supplied callback was invoked."""


def _json_snapshot(value) -> dict:
    """Accept bounded plain JSON data without coercing Python objects or keys."""
    nodes = 0

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_TOOL_JSON_NODES:
            raise ValueError("tool JSON exceeds structural limits")
        if type(item) is dict:
            if len(item) > MAX_TOOL_JSON_NODES:
                raise ValueError("tool JSON exceeds structural limits")
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError("tool JSON keys must be strings")
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif type(item) is list:
            if len(item) > MAX_TOOL_JSON_NODES:
                raise ValueError("tool JSON exceeds structural limits")
            for child in item:
                visit(child, depth + 1)
        elif type(item) is str:
            if len(item) > MAX_TOOL_JSON_BYTES:
                raise ValueError("tool JSON exceeds size limit")
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("tool JSON numbers must be finite")
        elif item is not None and type(item) not in {int, bool}:
            raise ValueError("tool JSON contains a non-JSON value")

    if type(value) is not dict:
        raise ValueError("tool JSON must be an object")
    visit(value, 0)
    chunks, size = [], 0
    for chunk in json.JSONEncoder(ensure_ascii=False, allow_nan=False).iterencode(value):
        encoded = chunk.encode("utf-8")
        size += len(encoded)
        if size > MAX_TOOL_JSON_BYTES:
            raise ValueError("tool JSON exceeds size limit")
        chunks.append(encoded)
    return decode_json_object(b"".join(chunks), MAX_TOOL_JSON_BYTES)


class _ToolSchema:
    """Keep validation separate from the mutable schema exposed to an SDK.

    No defaults/coercions, format checker, or reference retrieval is installed.
    A schema owner must supply complete local definitions and affordable rules;
    structural bounds do not bound regex or general JSON Schema evaluation time.
    """

    def __init__(self, parameters):
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError
        from referencing import Registry

        try:
            schema = _json_snapshot(parameters)
            if not schema:
                schema = {"type": "object", "properties": {}}
            dialect = schema.get("$schema", "https://json-schema.org/draft/2020-12/schema")
            if not isinstance(dialect, str) or dialect not in {
                "https://json-schema.org/draft/2020-12/schema", "https://json-schema.org/draft/2020-12/schema#",
            }:
                raise ValueError("unsupported tool schema dialect")
            Draft202012Validator.check_schema(schema)
        except (ValueError, TypeError, AttributeError, RecursionError, SchemaError):
            raise NativeToolSchemaError("tool schema must be bounded valid Draft 2020-12 JSON") from None
        self._schema = schema
        # An explicit empty registry does not fetch network or filesystem refs.
        self._validator = Draft202012Validator(schema, registry=Registry())

    def export(self) -> dict:
        return deepcopy(self._schema)

    def validate(self, arguments) -> None:
        from jsonschema.exceptions import ValidationError

        try:
            snapshot = _json_snapshot(arguments)
        except (ValueError, TypeError, RecursionError):
            raise _ToolArgumentsError("tool arguments must be bounded plain JSON") from None
        try:
            self._validator.validate(snapshot)
        except ValidationError:
            raise _ToolArgumentsError("tool arguments do not satisfy the supplied schema") from None
        except Exception:
            # Unresolved refs, invalid regex evaluation, and other validator
            # failures are configuration failures, not model-retry feedback.
            raise NativeToolSchemaError("tool schema could not be evaluated offline") from None
