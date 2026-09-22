"""Matched-case comparison of independently recomputed scan evidence."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from dspy_security_bench.jsonio import read_json_object
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.evidence import (
    IDENTITY_FIELDS,
    MAX_BYTES,
    MAX_ROWS,
    verify_scan_evidence,
)

CLAIM_BOUNDARY = (
    "This is a matched-case comparison of declared binary outcomes, not a ranking, "
    "causal effect, significance test, deployment approval, or authenticated execution. "
    "Cases are paired by exact scope and identity. Improvements do not erase newly "
    "failing cases. Security and task utility remain separate outcomes. Source policies "
    "and baselines can differ and are flagged; comparison thresholds are owner-selected. "
    "Shared task cases may be dependent and a single stochastic run can vary. Retain "
    "source evidence and independently pinned digests. Identifiers need sharing review."
)


def _counts() -> dict[str, int]:
    return {"cases": 0, "before_successes": 0, "after_successes": 0,
            "new_failures": 0, "new_successes": 0, "stable_successes": 0, "stable_failures": 0}


def _observe(counts: dict[str, int], before: int, after: int) -> None:
    counts["cases"] += 1
    counts["before_successes"] += before
    counts["after_successes"] += after
    counts[{(1, 0): "new_failures", (0, 1): "new_successes",
            (1, 1): "stable_successes", (0, 0): "stable_failures"}[(before, after)]] += 1


def compare_scan_evidence(
    before: dict, after: dict, *, max_new_security_failures: int = 0,
    max_new_utility_failures: int = 0,
    expected_before_sha256: str | None = None, expected_after_sha256: str | None = None,
) -> dict:
    """Reverify both inputs before comparing exactly aligned case outcomes."""
    before_report = verify_scan_evidence(before, expected_before_sha256)
    after_report = verify_scan_evidence(after, expected_after_sha256)
    for limit in (max_new_security_failures, max_new_utility_failures):
        if type(limit) is not int or not 0 <= limit <= MAX_ROWS:
            raise ValueError("new-failure limits must be integers from 0 to 100000")
    if canonical_sha256(before["scope"]) != canonical_sha256(after["scope"]):
        raise ValueError("comparison requires exactly matched scopes, including stable agent labels and benchmark versions")
    old = {tuple(row[field] for field in IDENTITY_FIELDS): row for row in before["observations"]}
    new = {tuple(row[field] for field in IDENTITY_FIELDS): row for row in after["observations"]}
    if old.keys() != new.keys():
        raise ValueError("comparison requires the same complete case matrix")
    security, utility = _counts(), _counts()
    cells = defaultdict(lambda: {"security": _counts(), "utility": _counts()})
    changed = []
    for key in sorted(old):
        first, second = old[key], new[key]
        group = key[:4]  # suite, agent, defense, attack
        for axis, total in (("security", security), ("utility", utility)):
            _observe(total, first[axis], second[axis])
            _observe(cells[group][axis], first[axis], second[axis])
        if any(first[axis] != second[axis] for axis in ("security", "utility")):
            changed.append({
                **dict(zip(IDENTITY_FIELDS, key, strict=True)),
                "before_security": first["security"], "after_security": second["security"],
                "before_utility": first["utility"], "after_utility": second["utility"],
            })
    result = {
        "schema_version": 1, "report_type": "DSPy Security Bench matched scan comparison",
        "protocol_version": "scan-comparison-v1",
        "before_evidence_sha256": before["evidence_sha256"],
        "after_evidence_sha256": after["evidence_sha256"],
        "scope_sha256": canonical_sha256(before["scope"]),
        "source_review": {
            "gate_policy_changed": canonical_sha256(before["policy"]) != canonical_sha256(after["policy"]),
            "baseline_changed": canonical_sha256(before["baseline"]) != canonical_sha256(after["baseline"]),
            "before_requirements_met": before_report["requirements_met"],
            "after_requirements_met": after_report["requirements_met"],
        },
        "comparison_policy": {"max_new_security_failures": max_new_security_failures,
                              "max_new_utility_failures": max_new_utility_failures},
        "summary": {"paired_cases": len(old), "changed_cases": len(changed),
                    "security": security, "utility": utility,
                    "comparison_requirements_met": security["new_failures"] <= max_new_security_failures
                    and utility["new_failures"] <= max_new_utility_failures},
        "cells": [{**dict(zip(IDENTITY_FIELDS[:4], key, strict=True)), **value}
                  for key, value in sorted(cells.items())],
        "changed_cases": changed, "claim_boundary": CLAIM_BOUNDARY,
    }
    result["comparison_sha256"] = canonical_sha256(result)
    return result


def verify_scan_comparison(report: dict, before: dict, after: dict) -> None:
    if not isinstance(report, dict) or not isinstance(report.get("comparison_policy"), dict):
        raise ValueError("comparison report is missing a policy")
    policy = report["comparison_policy"]
    if set(policy) != {"max_new_security_failures", "max_new_utility_failures"}:
        raise ValueError("invalid comparison policy")
    expected = compare_scan_evidence(before, after, **policy)
    if canonical_sha256(report) != canonical_sha256(expected):
        raise ValueError("scan comparison does not exactly recompute")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench scan compare", description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--before-sha256")
    parser.add_argument("--after-sha256")
    parser.add_argument("--max-new-security-failures", type=int, default=0)
    parser.add_argument("--max-new-utility-failures", type=int, default=0)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", type=Path, help="write a new comparison report")
    output.add_argument("--verify", type=Path, help="verify a saved report against both retained evidence sources")
    parser.add_argument("--html", type=Path, help="write a new self-contained offline review page")
    parser.add_argument("--fail-on-regression", action="store_true", help="exit 1 when either new-failure allowance is exceeded")
    args = parser.parse_args(argv)
    try:
        paths = [path for path in (args.json, args.html) if path is not None]
        if len({path.resolve() for path in paths}) != len(paths):
            raise ValueError("comparison outputs must be distinct")
        if any(path.exists() or path.is_symlink() or not path.parent.is_dir() for path in paths):
            raise ValueError("comparison outputs require new files in existing directories")
        before, after = read_json_object(args.before, MAX_BYTES), read_json_object(args.after, MAX_BYTES)
        report = compare_scan_evidence(
            before, after, max_new_security_failures=args.max_new_security_failures,
            max_new_utility_failures=args.max_new_utility_failures,
            expected_before_sha256=args.before_sha256, expected_after_sha256=args.after_sha256,
        )
        if args.verify:
            supplied = read_json_object(args.verify, MAX_BYTES)
            # CLI thresholds are independent anchors, not read from the untrusted report.
            if canonical_sha256(supplied) != canonical_sha256(report):
                raise ValueError("saved comparison differs from sources or caller-selected policy")
        artifacts = {}
        if args.json:
            raw = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
            artifacts[args.json] = raw
        if args.html:
            from dspy_security_bench.scan.compare_html import render_scan_comparison_html

            artifacts[args.html] = render_scan_comparison_html(report).encode("utf-8")
        for raw in artifacts.values():
            if len(raw) > MAX_BYTES:
                raise ValueError("comparison exceeds the 50 MB output limit")
        for path, raw in artifacts.items():
            with path.open("xb") as stream:
                stream.write(raw)
    except (OSError, ValueError, TypeError) as exc:
        print(f"[scan compare] invalid comparison: {type(exc).__name__}", file=sys.stderr)
        return 2
    summary = report["summary"]
    print(f"[scan compare] {summary['paired_cases']} matched cases; new security failures={summary['security']['new_failures']}; new utility failures={summary['utility']['new_failures']}; comparison_requirements_met={summary['comparison_requirements_met']}")
    if any(report["source_review"][key] for key in ("gate_policy_changed", "baseline_changed")):
        print("[scan compare] source policy/baseline changed; review separately from paired outcomes")
    print("[scan compare] descriptive matched-case evidence, not authenticated execution or statistical significance")
    return 1 if args.fail_on_regression and not summary["comparison_requirements_met"] else 0
