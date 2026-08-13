"""CLI for attested RepeatTwin execution envelopes."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.proofrun import capture_provenance, verify_github_attestation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench proofrun",
        description="Run RepeatTwin and create or verify a provenance-ready evidence bundle.",
    )
    commands = parser.add_subparsers(dest="command")

    run = commands.add_parser("run", help="run RepeatTwin and emit one attestation-ready bundle")
    target = run.add_mutually_exclusive_group(required=True)
    target.add_argument("--agent", help="module:callable returning an Agent")
    target.add_argument("--agent-model", help="LiteLLM model id for the built-in tool agent")
    run.add_argument("--name", help="display name override for --agent-model")
    run.add_argument("--trials", type=int, default=10)
    run.add_argument("--confidence", type=float, default=0.95)
    run.add_argument("--min-lower-bound", type=float, default=0.0)
    run.add_argument("--out", required=True, help="destination bundle JSON")
    run.add_argument("--report-out", help="optional standalone RepeatTwin JSON")
    run.add_argument("--submitter", required=True)
    run.add_argument("--agent-source", required=True)
    run.add_argument("--notes", default="")

    verify = commands.add_parser("verify", help="recompute a bundle and verify GitHub provenance")
    verify.add_argument("bundle")
    verify.add_argument("--attestation-repo", help="owner/repository; defaults to bundle metadata")
    verify.add_argument("--minimum-trials", type=int, default=5)
    verify.add_argument("--offline", action="store_true", help="skip cryptographic provenance lookup")
    verify.add_argument("--require-trusted-builder", action="store_true")
    verify.add_argument(
        "--allow-self-hosted-runner",
        action="store_true",
        help="accept GitHub attestations produced on self-hosted runners",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "run":
        return _run(args)
    if args.command == "verify":
        return _verify(args)
    return 2


def _run(args) -> int:
    from dspy_security_bench.procurement.repeat import (
        create_submission_bundle,
        render_repeat_terminal,
        run_repeat_twin,
    )

    if args.trials < 2:
        print("[proofrun] --trials must be at least 2", file=sys.stderr)
        return 2
    if not 0 < args.confidence < 1:
        print("[proofrun] --confidence must be between 0 and 1", file=sys.stderr)
        return 2
    if not 0 <= args.min_lower_bound <= 1:
        print("[proofrun] --min-lower-bound must be between 0 and 1", file=sys.stderr)
        return 2
    try:
        factory = _agent_factory(args)
        report = run_repeat_twin(
            factory(),
            trials=args.trials,
            confidence_level=args.confidence,
            agent_factory=factory,
            progress=lambda current, total: print(
                f"[proofrun] completed trial {current}/{total}", file=sys.stderr
            ),
        )
        bundle = create_submission_bundle(
            report.to_dict(),
            submitter=args.submitter,
            agent_source_url=args.agent_source,
            notes=args.notes,
            provenance=capture_provenance(),
        )
        _write_json(Path(args.out), bundle)
        if args.report_out:
            _write_json(Path(args.report_out), report.to_dict())
    except Exception as exc:
        print(f"[proofrun] failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    print(render_repeat_terminal(report))
    print(f"\n[proofrun] wrote {args.out}")
    print(f"[proofrun] bundle sha256: {bundle['bundle_sha256']}")
    print(f"[proofrun] evidence tier before signature verification: {bundle['submission']['attestation']}")
    lower = report.summary.attack_resistance.lower
    if lower < args.min_lower_bound:
        print(
            f"[proofrun] gate failed: lower bound {lower:.1%} < {args.min_lower_bound:.1%}",
            file=sys.stderr,
        )
        return 1
    print(f"[proofrun] gate passed: lower bound {lower:.1%} >= {args.min_lower_bound:.1%}")
    return 0


def _verify(args) -> int:
    from dspy_security_bench.procurement.repeat import verify_submission_bundle

    path = Path(args.bundle)
    try:
        bundle = json.loads(path.read_text())
        integrity = verify_submission_bundle(bundle, minimum_trials=args.minimum_trials)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[INVALID] {path}: {exc}", file=sys.stderr)
        return 2

    print(f"Integrity: {'valid' if integrity.valid else 'INVALID'}")
    print(f"Leaderboard eligibility: {'yes' if integrity.community_eligible else 'no'}")
    print(f"Offline evidence tier: {integrity.evidence_tier}")
    for error in integrity.errors:
        print(f"  error: {error}")
    for warning in integrity.warnings:
        print(f"  note: {warning}")
    if not integrity.valid or not integrity.community_eligible:
        return 1
    if args.offline:
        return 0

    attestation = verify_github_attestation(
        path,
        bundle,
        repository=args.attestation_repo,
        require_trusted_builder=args.require_trusted_builder,
        deny_self_hosted=not args.allow_self_hosted_runner,
    )
    print(f"Cryptographic evidence tier: {attestation.evidence_tier}")
    if attestation.run_url:
        print(f"Workflow run: {attestation.run_url}")
    for error in attestation.errors:
        print(f"  error: {error}")
    for warning in attestation.warnings:
        print(f"  note: {warning}")
    return 0 if attestation.verified else 1


def _agent_factory(args):
    if args.agent:
        module_name, separator, attribute = args.agent.partition(":")
        if not separator or not module_name or not attribute:
            raise ValueError(f"--agent must be module:callable, got {args.agent!r}")
        return getattr(importlib.import_module(module_name), attribute)
    from dspy_security_bench.agents import LiteLLMFunctionCallingAgent

    return lambda: LiteLLMFunctionCallingAgent(
        args.agent_model, name=args.name or args.agent_model
    )


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
