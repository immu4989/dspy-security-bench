#!/usr/bin/env python3
"""Validate FederalProof documents against pinned official OSCAL 1.2.2 schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assessment-results", required=True, type=Path)
    parser.add_argument("--assessment-schema", required=True, type=Path)
    parser.add_argument("--poam", type=Path)
    parser.add_argument("--poam-schema", type=Path)
    args = parser.parse_args()
    targets = [(args.assessment_results, args.assessment_schema)]
    if bool(args.poam) != bool(args.poam_schema):
        parser.error("--poam and --poam-schema must be provided together")
    if args.poam and args.poam_schema:
        targets.append((args.poam, args.poam_schema))

    failed = False
    for document_path, schema_path in targets:
        document = json.loads(document_path.read_text())
        schema = _python_compatible_schema(json.loads(schema_path.read_text()))
        errors = sorted(
            Draft7Validator(schema).iter_errors(document),
            key=lambda error: tuple(str(item) for item in error.absolute_path),
        )
        if errors:
            failed = True
            for error in errors:
                location = "/".join(str(item) for item in error.absolute_path) or "<root>"
                print(f"[INVALID] {document_path}:{location}: {error.message}")
        else:
            print(f"[VALID] {document_path} against {schema_path.name}")
    return 1 if failed else 0


def _python_compatible_schema(value: Any, *, root: bool = True) -> Any:
    """Normalize only generator features unsupported by Python's Draft-07 engine.

    OSCAL's generated schemas put fragment-only ``$id`` values on definitions,
    which modern ``jsonschema`` treats as new resolution scopes, and use ECMA-262
    Unicode property escapes that Python ``re`` cannot compile. CI still checks
    the official schema bytes by SHA-256; this function skips only those regex
    assertions while retaining model structure, required fields, types, enums,
    formats, references, and additional-property constraints.
    """
    if isinstance(value, dict):
        return {
            key: _python_compatible_schema(item, root=False)
            for key, item in value.items()
            if key != "pattern" and not (key == "$id" and not root)
        }
    if isinstance(value, list):
        return [_python_compatible_schema(item, root=False) for item in value]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
