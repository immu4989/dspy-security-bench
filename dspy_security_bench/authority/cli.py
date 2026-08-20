"""AuthorityTwin command-line interface."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from dspy_security_bench.authority.protocol import (
    DISCLAIMER,
    POLICY_PROFILE,
    SCENARIO_VERSION,
    build_authority_scenarios,
    policy_sha256,
    protocol_sha256,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench authority",
        description=(
            "Test agent identity and delegated-authorization adapters with frozen clean/adversarial twins."
        ),
    )
    commands = parser.add_subparsers(dest="command")

    describe = commands.add_parser("describe", help="show protocol identity and conformance cases")
    describe.add_argument("--json", action="store_true", dest="as_json")

    demo = commands.add_parser("demo", help="compare bounded and ambient reference adapters")
    demo.add_argument("--reference", choices=("both", "bounded", "ambient"), default="both")
    demo.add_argument("--json", action="store_true", dest="as_json")

    run = commands.add_parser("run", help="run one deterministic AuthorityTwin trial")
    _target(run)
    run.add_argument("--json-out")
    run.add_argument("--min-attack-resistance", type=float, default=0.0)

    repeat = commands.add_parser("repeat", help="run fresh-adapter trials with Wilson intervals")
    _target(repeat)
    repeat.add_argument("--trials", type=int, default=10)
    repeat.add_argument("--confidence", type=float, default=0.95)
    repeat.add_argument("--report-out", required=True)
    repeat.add_argument("--min-lower-bound", type=float, default=0.0)

    bundle = commands.add_parser(
        "bundle", help="wrap a repeated report in content-addressed evidence"
    )
    bundle.add_argument("report")
    bundle.add_argument("--out", required=True)
    bundle.add_argument("--submitter", required=True)
    bundle.add_argument("--adapter-source", required=True)
    bundle.add_argument("--notes", default="")

    verify = commands.add_parser("verify", help="recompute a report or evidence bundle offline")
    verify.add_argument("path")
    verify.add_argument("--minimum-trials", type=int, default=5)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "describe":
        return _describe(args)
    if args.command == "demo":
        return _demo(args)
    if args.command == "run":
        return _run(args)
    if args.command == "repeat":
        return _repeat(args)
    if args.command == "bundle":
        return _bundle(args)
    if args.command == "verify":
        return _verify(args)
    return 2


def _target(parser: argparse.ArgumentParser) -> None:
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--adapter", help="module:callable returning an AuthorityAdapter")
    target.add_argument(
        "--reference",
        choices=("bounded", "ambient"),
        help="zero-cost conformance fixture (defaults to bounded)",
    )


def _describe(args) -> int:
    scenarios = build_authority_scenarios()
    payload = {
        "scenario_version": SCENARIO_VERSION,
        "protocol_sha256": protocol_sha256(),
        "policy_sha256": policy_sha256(),
        "policy_id": POLICY_PROFILE["policy_id"],
        "methodology": "clean/adversarial delegated-authorization conformance twins",
        "pairs": [
            {
                "pair_id": item.pair_id,
                "title": item.title,
                "risk": item.risk,
                "control": item.control,
                "injected_expected_outcome": next(
                    candidate.expected_outcome
                    for candidate in scenarios
                    if candidate.pair_id == item.pair_id and candidate.variant == "injected"
                ),
            }
            for item in scenarios
            if item.variant == "clean"
        ],
        "metrics": [
            "attack_resistance",
            "clean_mission_utility",
            "injected_authorization_accuracy",
            "harm_containment",
            "receipt_integrity",
            "false_allows",
        ],
        "disclaimer": DISCLAIMER,
    }
    if args.as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"AuthorityTwin ({SCENARIO_VERSION})")
        print(f"Protocol sha256: {payload['protocol_sha256']}")
        print(f"Policy sha256: {payload['policy_sha256']}")
        for pair in payload["pairs"]:
            print(f"  - {pair['pair_id']}: {pair['title']} [{pair['control']}]")
        print(DISCLAIMER)
    return 0


def _demo(args) -> int:
    from dspy_security_bench.authority.adapter import (
        build_ambient_authority_adapter,
        build_bounded_authority_adapter,
    )
    from dspy_security_bench.authority.benchmark import render_terminal, run_authority_twin

    factories = {
        "bounded": build_bounded_authority_adapter,
        "ambient": build_ambient_authority_adapter,
    }
    names = factories if args.reference == "both" else (args.reference,)
    reports = [
        run_authority_twin(factories[name](), adapter_factory=factories[name]) for name in names
    ]
    if args.as_json:
        print(json.dumps([report.to_dict() for report in reports], indent=2, sort_keys=True))
    else:
        print("\n\n".join(render_terminal(report) for report in reports))
    return 0


def _run(args) -> int:
    from dspy_security_bench.authority.benchmark import render_terminal, run_authority_twin

    if not 0 <= args.min_attack_resistance <= 1:
        print("[authority] --min-attack-resistance must be between 0 and 1", file=sys.stderr)
        return 2
    try:
        factory = _adapter_factory(args)
        report = run_authority_twin(factory(), adapter_factory=factory)
    except (ImportError, TypeError, ValueError) as exc:
        print(f"[authority] run failed: {exc}", file=sys.stderr)
        return 2
    print(render_terminal(report))
    if args.json_out:
        _write_json(Path(args.json_out), report.to_dict())
        print(f"[authority] wrote {args.json_out}")
    observed = float(report.summary["attack_resistance"])
    if observed < args.min_attack_resistance:
        print(
            f"[authority] gate failed: {observed:.1%} < {args.min_attack_resistance:.1%}",
            file=sys.stderr,
        )
        return 1
    return 0


def _repeat(args) -> int:
    from dspy_security_bench.authority.repeat import run_repeat_authority_twin

    if args.trials < 2:
        print("[authority] --trials must be at least 2", file=sys.stderr)
        return 2
    if not 0 < args.confidence < 1 or not 0 <= args.min_lower_bound <= 1:
        print("[authority] confidence and gate values must be valid probabilities", file=sys.stderr)
        return 2
    try:
        report = run_repeat_authority_twin(
            _adapter_factory(args),
            trials=args.trials,
            confidence_level=args.confidence,
            progress=lambda current, total: print(f"[authority] trial {current}/{total}"),
        )
    except (ImportError, TypeError, ValueError) as exc:
        print(f"[authority] repeat failed: {exc}", file=sys.stderr)
        return 2
    _write_json(Path(args.report_out), report.to_dict())
    estimate = report.summary.attack_resistance
    print(
        f"Attack resistance: {estimate.rate:.1%} "
        f"({estimate.confidence_level:.0%} Wilson {estimate.lower:.1%}–{estimate.upper:.1%})"
    )
    print(f"[authority] wrote {args.report_out}")
    if estimate.lower < args.min_lower_bound:
        print(
            f"[authority] gate failed: lower bound {estimate.lower:.1%} "
            f"< {args.min_lower_bound:.1%}",
            file=sys.stderr,
        )
        return 1
    return 0


def _bundle(args) -> int:
    from dspy_security_bench.authority.repeat import create_authority_submission_bundle

    try:
        report = json.loads(Path(args.report).read_text())
        bundle = create_authority_submission_bundle(
            report,
            submitter=args.submitter,
            adapter_source_url=args.adapter_source,
            notes=args.notes,
        )
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[authority] bundle failed: {exc}", file=sys.stderr)
        return 2
    _write_json(Path(args.out), bundle)
    print(f"[authority] wrote {args.out}")
    print(f"Bundle sha256: {bundle['bundle_sha256']}")
    return 0


def _verify(args) -> int:
    from dspy_security_bench.authority.benchmark import verify_authority_report
    from dspy_security_bench.authority.repeat import (
        BUNDLE_TYPE,
        REPEAT_REPORT_TYPE,
        verify_authority_submission_bundle,
        verify_repeat_authority_report,
    )

    try:
        payload = json.loads(Path(args.path).read_text())
        if not isinstance(payload, Mapping):
            raise ValueError("JSON root must be an object")
        warnings: tuple[str, ...] = ()
        if payload.get("bundle_type") == BUNDLE_TYPE:
            result = verify_authority_submission_bundle(payload, minimum_trials=args.minimum_trials)
            errors = result.errors
            warnings = result.warnings
            print(f"Integrity: {'valid' if result.valid else 'INVALID'}")
            print(f"Authority registry eligibility: {'yes' if result.community_eligible else 'no'}")
        elif payload.get("report_type") == REPEAT_REPORT_TYPE:
            errors = verify_repeat_authority_report(payload)
            print(f"Integrity: {'valid' if not errors else 'INVALID'}")
        else:
            errors = verify_authority_report(payload)
            print(f"Integrity: {'valid' if not errors else 'INVALID'}")
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[INVALID] {exc}", file=sys.stderr)
        return 2
    for error in errors:
        print(f"  error: {error}")
    for warning in warnings:
        print(f"  note: {warning}")
    return 0 if not errors else 2


def _adapter_factory(args) -> Callable:
    if args.adapter:
        module_name, separator, attribute = args.adapter.partition(":")
        if not separator or not module_name or not attribute:
            raise ValueError(f"--adapter must be module:callable, got {args.adapter!r}")
        callback = getattr(importlib.import_module(module_name), attribute)
        if not callable(callback):
            raise ValueError(f"{args.adapter!r} does not resolve to a callable")
        return callback
    from dspy_security_bench.authority.adapter import (
        build_ambient_authority_adapter,
        build_bounded_authority_adapter,
    )

    return (
        build_ambient_authority_adapter
        if args.reference == "ambient"
        else build_bounded_authority_adapter
    )


def _write_json(path: Path, payload: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
