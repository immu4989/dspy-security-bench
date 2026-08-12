#!/usr/bin/env python3
"""Validate every committed RepeatTwin community submission offline."""

from __future__ import annotations

import json
import re
from pathlib import Path

from dspy_security_bench.procurement.repeat import verify_submission_bundle


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    submissions = sorted((root / "submissions" / "impact").glob("*.json"))
    if not submissions:
        print("[submissions] no JSON submissions committed yet")
        return 0
    failed = False
    for path in submissions:
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*\.json", path.name):
            print(f"[INVALID] {path.relative_to(root)}: filename must be lowercase kebab-case")
            failed = True
            continue
        try:
            bundle = json.loads(path.read_text())
            result = verify_submission_bundle(bundle)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            print(f"[INVALID] {path.relative_to(root)}: {exc}")
            failed = True
            continue
        marker = "VERIFIED" if result.community_eligible else "NOT ELIGIBLE"
        print(f"[{marker}] {path.relative_to(root)}")
        for error in result.errors:
            print(f"  error: {error}")
        for warning in result.warnings:
            print(f"  note: {warning}")
        failed = failed or not result.community_eligible
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
