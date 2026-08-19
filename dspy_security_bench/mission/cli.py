"""MissionForge CLI for authoring and running declarative assurance packs."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

import yaml

from dspy_security_bench.mission.loader import (
    load_mission_pack,
    mission_pack_template,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench pack",
        description=(
            "Author and run data-only MissionPacks with deterministic clean/injected scoring."
        ),
    )
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("list", help="list packaged MissionPacks")

    init = commands.add_parser("init", help="create a safe MissionPack starter file")
    init.add_argument("--out", default="mission-pack.yaml")
    init.add_argument("--force", action="store_true")

    validate = commands.add_parser("validate", help="validate a MissionPack and its references")
    validate.add_argument("pack")

    describe = commands.add_parser("describe", help="show protocol identity, cases, and metrics")
    describe.add_argument("pack", nargs="?", default="source-twin")
    describe.add_argument("--json", action="store_true", dest="as_json")

    run = commands.add_parser("run", help="run one clean/injected MissionPack trial")
    run.add_argument("pack", nargs="?", default="source-twin")
    _target(run)
    run.add_argument("--json-out")
    run.add_argument("--min-attack-resistance", type=float, default=0.0)

    repeat = commands.add_parser("repeat", help="run fresh-agent trials with Wilson intervals")
    repeat.add_argument("pack", nargs="?", default="source-twin")
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
    bundle.add_argument("--agent-source", required=True)
    bundle.add_argument("--notes", default="")

    verify = commands.add_parser("verify", help="recompute a pack, report, or bundle offline")
    verify.add_argument("path")
    verify.add_argument("--minimum-trials", type=int, default=5)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "list":
        print("source-twin-v1  SourceTwin Public-Service Grounding Protocol  (built-in)")
        return 0
    if args.command == "init":
        return _init(args)
    if args.command == "validate":
        return _validate(args)
    if args.command == "describe":
        return _describe(args)
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
    target.add_argument("--agent", help="module:callable returning an Agent")
    target.add_argument("--agent-model", help="LiteLLM model id")
    target.add_argument(
        "--reference", choices=("bounded", "vulnerable"), help="zero-cost scorer fixture"
    )
    parser.add_argument("--name", help="display name override for --agent-model")


def _init(args) -> int:
    path = Path(args.out)
    if path.exists() and not args.force:
        print(f"[pack] kept existing {path} (use --force to replace)", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(mission_pack_template(), sort_keys=False), encoding="utf-8")
    print(f"[pack] created {path}")
    print(f"Next: dspy-security-bench pack validate {path}")
    return 0


def _validate(args) -> int:
    try:
        pack = load_mission_pack(args.pack)
    except ValueError as exc:
        print(f"[INVALID] {exc}", file=sys.stderr)
        return 2
    print(f"[VALID] {pack.pack_id}@{pack.version}")
    print(f"Protocol sha256: {pack.protocol_sha256}")
    print(f"Cases: {len(pack.cases)} clean/injected pairs")
    return 0


def _describe(args) -> int:
    try:
        pack = load_mission_pack(args.pack)
    except ValueError as exc:
        print(f"[INVALID] {exc}", file=sys.stderr)
        return 2
    payload = {
        "pack_id": pack.pack_id,
        "version": pack.version,
        "name": pack.name,
        "domain": pack.raw["domain"],
        "protocol_sha256": pack.protocol_sha256,
        "methodology": pack.raw["methodology"],
        "pairs": [
            {"case_id": case["id"], "title": case["title"], "risk": case["risk"]}
            for case in pack.cases
        ],
        "metrics": [
            "attack_resistance",
            "clean_mission_utility",
            "decision_invariance",
            "citation_faithfulness",
            "citation_completeness",
            "citation_sufficiency",
            "authoritative_source_preference",
        ],
        "disclaimer": pack.raw["disclaimer"],
    }
    if args.as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{pack.name} ({pack.pack_id}@{pack.version})")
        print(f"Protocol sha256: {pack.protocol_sha256}")
        print(f"Method: {pack.raw['methodology']}")
        for pair in payload["pairs"]:
            print(f"  - {pair['case_id']}: {pair['title']}")
        print(pack.raw["disclaimer"])
    return 0


def _run(args) -> int:
    from dspy_security_bench.mission.benchmark import render_terminal, run_mission_pack

    if not 0 <= args.min_attack_resistance <= 1:
        print("[pack] --min-attack-resistance must be between 0 and 1", file=sys.stderr)
        return 2
    try:
        pack = load_mission_pack(args.pack)
        factory = _agent_factory(args)
        report = run_mission_pack(factory(), pack, agent_factory=factory)
    except (ImportError, TypeError, ValueError) as exc:
        print(f"[pack] run failed: {exc}", file=sys.stderr)
        return 2
    print(render_terminal(report))
    if args.json_out:
        _write_json(Path(args.json_out), report.to_dict())
        print(f"[pack] wrote {args.json_out}")
    observed = float(report.summary["attack_resistance"])
    if observed < args.min_attack_resistance:
        print(
            f"[pack] gate failed: {observed:.1%} < {args.min_attack_resistance:.1%}",
            file=sys.stderr,
        )
        return 1
    return 0


def _repeat(args) -> int:
    from dspy_security_bench.mission.repeat import run_repeat_mission_pack

    if args.trials < 2:
        print("[pack] --trials must be at least 2", file=sys.stderr)
        return 2
    if not 0 < args.confidence < 1 or not 0 <= args.min_lower_bound <= 1:
        print("[pack] confidence and gate values must be valid probabilities", file=sys.stderr)
        return 2
    try:
        pack = load_mission_pack(args.pack)
        report = run_repeat_mission_pack(
            _agent_factory(args),
            pack,
            trials=args.trials,
            confidence_level=args.confidence,
            progress=lambda current, total: print(f"[pack] trial {current}/{total}"),
        )
    except (ImportError, TypeError, ValueError) as exc:
        print(f"[pack] repeat failed: {exc}", file=sys.stderr)
        return 2
    payload = report.to_dict()
    _write_json(Path(args.report_out), payload)
    estimate = report.summary.attack_resistance
    print(
        f"Attack resistance: {estimate.rate:.1%} ({estimate.confidence_level:.0%} Wilson {estimate.lower:.1%}–{estimate.upper:.1%})"
    )
    print(f"[pack] wrote {args.report_out}")
    if estimate.lower < args.min_lower_bound:
        print(
            f"[pack] gate failed: lower bound {estimate.lower:.1%} < {args.min_lower_bound:.1%}",
            file=sys.stderr,
        )
        return 1
    return 0


def _bundle(args) -> int:
    from dspy_security_bench.mission.repeat import create_source_submission_bundle

    try:
        report = json.loads(Path(args.report).read_text())
        bundle = create_source_submission_bundle(
            report,
            submitter=args.submitter,
            agent_source_url=args.agent_source,
            notes=args.notes,
        )
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[pack] bundle failed: {exc}", file=sys.stderr)
        return 2
    _write_json(Path(args.out), bundle)
    print(f"[pack] wrote {args.out}")
    print(f"Bundle sha256: {bundle['bundle_sha256']}")
    return 0


def _verify(args) -> int:
    from dspy_security_bench.mission.benchmark import verify_mission_report
    from dspy_security_bench.mission.repeat import (
        BUNDLE_TYPE,
        REPEAT_REPORT_TYPE,
        verify_repeat_source_report,
        verify_source_submission_bundle,
    )

    path = Path(args.path)
    try:
        if path.suffix.lower() in {".yaml", ".yml"}:
            pack = load_mission_pack(path)
            print(f"[VALID] {pack.pack_id}@{pack.version}: {pack.protocol_sha256}")
            return 0
        payload = json.loads(path.read_text())
        if not isinstance(payload, Mapping):
            raise ValueError("JSON root must be an object")
        if payload.get("bundle_type") == BUNDLE_TYPE:
            result = verify_source_submission_bundle(payload, minimum_trials=args.minimum_trials)
            errors = result.errors
            warnings = result.warnings
            print(f"Integrity: {'valid' if result.valid else 'INVALID'}")
            print(f"Source registry eligibility: {'yes' if result.community_eligible else 'no'}")
        elif payload.get("report_type") == REPEAT_REPORT_TYPE:
            errors = verify_repeat_source_report(payload)
            warnings = ()
            print(f"Integrity: {'valid' if not errors else 'INVALID'}")
        else:
            errors = verify_mission_report(payload)
            warnings = ()
            print(f"Integrity: {'valid' if not errors else 'INVALID'}")
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[INVALID] {exc}", file=sys.stderr)
        return 2
    for error in errors:
        print(f"  error: {error}")
    for warning in warnings:
        print(f"  note: {warning}")
    return 0 if not errors else 2


def _agent_factory(args) -> Callable:
    if args.reference:
        from dspy_security_bench.mission.agents import (
            build_bounded_source_reference,
            build_vulnerable_source_reference,
        )

        return (
            build_bounded_source_reference
            if args.reference == "bounded"
            else build_vulnerable_source_reference
        )
    if args.agent:
        module_name, separator, attribute = args.agent.partition(":")
        if not separator or not module_name or not attribute:
            raise ValueError(f"--agent must be module:callable, got {args.agent!r}")
        callback = getattr(importlib.import_module(module_name), attribute)
        if not callable(callback):
            raise ValueError(f"{args.agent!r} does not resolve to a callable")
        return callback
    if args.agent_model:
        from dspy_security_bench.agents import LiteLLMFunctionCallingAgent

        return lambda: LiteLLMFunctionCallingAgent(
            args.agent_model, name=args.name or args.agent_model
        )
    from dspy_security_bench.mission.agents import build_bounded_source_reference

    return build_bounded_source_reference


def _write_json(path: Path, payload: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
