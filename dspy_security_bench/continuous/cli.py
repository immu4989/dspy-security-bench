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
    controller = commands.add_parser(
        "controller", help="run the observe-only assurance controller and hash-chained timeline"
    )
    controller_commands = controller.add_subparsers(dest="controller_command")
    controller_init = controller_commands.add_parser(
        "init", help="write a one-job observation plan"
    )
    controller_init.add_argument("--plan-id", required=True)
    controller_init.add_argument("--evaluation-time", type=int, required=True)
    controller_init.add_argument("--job-id", required=True)
    controller_init.add_argument("--evidence-ref", required=True)
    controller_init.add_argument("--kind", required=True, dest="expected_evidence_kind")
    controller_init.add_argument("--last-updated-at", type=int, required=True)
    controller_init.add_argument("--max-age", type=int, required=True, dest="max_age_seconds")
    controller_init.add_argument("--max-regression", type=float, default=0.0)
    controller_init.add_argument("--baseline")
    controller_init.add_argument("--out", required=True)
    controller_observe = controller_commands.add_parser(
        "observe", help="verify all evidence without taking action"
    )
    controller_observe.add_argument("plan")
    controller_observe.add_argument("--evidence-root", required=True)
    controller_observe.add_argument("--out", required=True)
    controller_append = controller_commands.add_parser(
        "append", help="append an observation to a timeline"
    )
    controller_append.add_argument("observation")
    controller_append.add_argument("--timeline")
    controller_append.add_argument("--timeline-id", required=True)
    controller_append.add_argument("--out", required=True)
    controller_verify = controller_commands.add_parser(
        "verify", help="verify a plan, observation, or timeline"
    )
    controller_verify.add_argument("path")
    controller_verify.add_argument("--evidence-root")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "controller":
        return _controller(args)
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
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _controller(args) -> int:
    from dspy_security_bench.continuous.controller import (
        OBSERVATION_TYPE,
        PLAN_TYPE,
        TIMELINE_TYPE,
        append_timeline,
        build_plan,
        observe_plan,
        verify_observation,
        verify_plan,
        verify_timeline,
    )

    if args.controller_command is None:
        print("Usage: dspy-security-bench watch controller <init|observe|append|verify>")
        return 0

    def loader(root: str):
        root_path = Path(root).resolve()

        def load(reference: str) -> dict:
            candidate = (root_path / reference).resolve()
            if root_path not in candidate.parents:
                raise ValueError("evidence_ref escapes --evidence-root")
            return _read(str(candidate))

        return load

    try:
        if args.controller_command == "init":
            baseline = _read(args.baseline) if args.baseline else None
            plan = build_plan(
                plan_id=args.plan_id,
                evaluation_time=args.evaluation_time,
                jobs=[
                    {
                        "job_id": args.job_id,
                        "evidence_ref": args.evidence_ref,
                        "expected_evidence_kind": args.expected_evidence_kind,
                        "last_updated_at": args.last_updated_at,
                        "max_age_seconds": args.max_age_seconds,
                        "max_regression": args.max_regression,
                        "baseline": baseline,
                    }
                ],
            )
            _write(args.out, plan)
            print(f"[watch] wrote observe-only plan {args.out}")
            return 0
        if args.controller_command == "observe":
            report = observe_plan(_read(args.plan), loader(args.evidence_root))
            _write(args.out, report)
            print(f"[watch] {report['summary']['status']}: wrote {args.out}; actions_taken=0")
            return 1 if report["summary"]["status"] == "review_required" else 0
        if args.controller_command == "append":
            previous = _read(args.timeline) if args.timeline else None
            timeline = append_timeline(
                previous, _read(args.observation), timeline_id=args.timeline_id
            )
            _write(args.out, timeline)
            print(f"[watch] appended evidence timeline {args.out}")
            return 0
        payload = _read(args.path)
        kind = payload.get("controller_type")
        if kind == PLAN_TYPE:
            errors = verify_plan(payload)
        elif kind == TIMELINE_TYPE:
            errors = verify_timeline(payload)
        elif kind == OBSERVATION_TYPE:
            if not args.evidence_root:
                raise ValueError("--evidence-root is required to recompute an observation")
            errors = verify_observation(payload, loader(args.evidence_root))
        else:
            raise ValueError("unsupported controller evidence type")
        if errors:
            raise ValueError("; ".join(errors))
        print(f"[watch] verified {args.path}")
        return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[watch] controller failed: {exc}", file=sys.stderr)
        return 2
