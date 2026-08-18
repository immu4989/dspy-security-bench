#!/usr/bin/env python3
"""Export safe, scalar ProofRun fields to GitHub Actions outputs."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: proofrun_action_metadata.py BUNDLE.json")
    payload = json.loads(Path(sys.argv[1]).read_text())
    summary = payload["report"]["summary"]
    if payload.get("bundle_type") == "dspy-security-bench-control-evidence-submission":
        containment = summary.get("harm_containment_efficacy")
        recovery = summary.get("safe_mission_recovery")
        preservation = summary.get("clean_utility_preservation")
        primary = containment or summary["controlled_harm_free"]
        values = {
            "evidence-kind": "control",
            "bundle-sha256": payload["bundle_sha256"],
            "attack-resistance": summary["controlled_attack_resistance"]["rate"],
            "lower-bound": primary["lower"],
            "containment": _rate(containment),
            "containment-lower-bound": _lower(containment),
            "safe-recovery": _rate(recovery),
            "clean-preservation": _rate(preservation),
        }
    else:
        resistance = summary["attack_resistance"]
        kind = (
            "incident"
            if payload.get("bundle_type")
            == "dspy-security-bench-incident-evidence-submission"
            else "impact"
        )
        values = {
            "evidence-kind": kind,
            "bundle-sha256": payload["bundle_sha256"],
            "attack-resistance": resistance["rate"],
            "lower-bound": resistance["lower"],
            "containment": "",
            "containment-lower-bound": "",
            "safe-recovery": "",
            "clean-preservation": "",
        }
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        raise SystemExit("GITHUB_OUTPUT is not set")
    with Path(output).open("a") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")
    return 0


def _rate(estimate: dict | None) -> float | str:
    return estimate["rate"] if estimate is not None else ""


def _lower(estimate: dict | None) -> float | str:
    return estimate["lower"] if estimate is not None else ""


if __name__ == "__main__":
    raise SystemExit(main())
