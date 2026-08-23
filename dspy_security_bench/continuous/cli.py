"""ContinuousProof CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench watch")
    commands = parser.add_subparsers(dest="command")
    baseline = commands.add_parser("baseline", help="capture a verified evidence baseline")
    baseline.add_argument("evidence")
    baseline.add_argument("--label", required=True)
    baseline.add_argument("--out", required=True)
    compare = commands.add_parser("compare", help="compare baseline and candidate snapshots")
    compare.add_argument("baseline")
    compare.add_argument("candidate")
    compare.add_argument("--max-regression", type=float, default=0.0)
    compare.add_argument("--out", required=True)
    verify = commands.add_parser("verify", help="verify a snapshot or drift report")
    verify.add_argument("path")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    from dspy_security_bench.continuous.proof import (
        build_evidence_snapshot,
        compare_evidence,
        verify_continuous_proof,
    )

    try:
        if args.command == "baseline":
            evidence = _read(args.evidence)
            payload = build_evidence_snapshot(evidence, label=args.label)
            _write(args.out, payload)
            print(f"[watch] captured verified baseline {args.out}")
            return 0
        payload = _read(args.path if args.command == "verify" else args.baseline)
        if args.command == "verify":
            errors = verify_continuous_proof(payload)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[watch] verified {args.path}")
            return 0
        candidate = _read(args.candidate)
        report = compare_evidence(payload, candidate, max_regression=args.max_regression)
        _write(args.out, report)
        print(f"[watch] {report['status']}: wrote {args.out}")
        return 1 if report["status"] == "review" else 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[watch] failed: {exc}", file=sys.stderr)
        return 2


def _read(path: str) -> dict:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write(path: str, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
