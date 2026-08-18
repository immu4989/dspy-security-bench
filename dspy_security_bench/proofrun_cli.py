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
        description=(
            "Run RepeatTwin or RepeatControlTwin and create or verify a "
            "provenance-ready evidence bundle."
        ),
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

    control = commands.add_parser(
        "control", help="run RepeatControlTwin and emit attestation-ready control evidence"
    )
    control_target = control.add_mutually_exclusive_group(required=True)
    control_target.add_argument("--agent", help="module:callable returning an Agent")
    control_target.add_argument("--agent-model", help="LiteLLM model id for the built-in agent")
    control.add_argument("--name", help="display name override for --agent-model")
    control.add_argument("--policy", required=True, help="validated tool-policy YAML")
    control.add_argument("--policy-source", required=True, help="public HTTPS policy source")
    control.add_argument("--approval-handler", help="optional module:callable approval handler")
    control.add_argument("--capture-arguments", action="store_true")
    control.add_argument("--trials", type=int, default=10)
    control.add_argument("--confidence", type=float, default=0.95)
    control.add_argument("--min-containment-lower-bound", type=float, default=0.0)
    control.add_argument("--min-controlled-harm-free-lower-bound", type=float, default=0.0)
    control.add_argument("--min-clean-preservation-lower-bound", type=float, default=0.0)
    control.add_argument("--min-controlled-resistance-lower-bound", type=float, default=0.0)
    control.add_argument("--max-unstable-pairs", type=int, default=5)
    control.add_argument("--out", required=True, help="destination bundle JSON")
    control.add_argument("--report-out", help="optional standalone RepeatControlTwin JSON")
    control.add_argument("--card-out", help="optional shareable SVG evidence card")
    control.add_argument("--submitter", required=True)
    control.add_argument("--agent-source", required=True)
    control.add_argument("--notes", default="")

    verify = commands.add_parser("verify", help="recompute a bundle and verify GitHub provenance")
    verify.add_argument("bundle")
    verify.add_argument("--attestation-repo", help="owner/repository; defaults to bundle metadata")
    verify.add_argument("--minimum-trials", type=int, default=5)
    verify.add_argument(
        "--offline", action="store_true", help="skip cryptographic provenance lookup"
    )
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
    if args.command == "control":
        return _control(args)
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
    print(
        f"[proofrun] evidence tier before signature verification: {bundle['submission']['attestation']}"
    )
    lower = report.summary.attack_resistance.lower
    if lower < args.min_lower_bound:
        print(
            f"[proofrun] gate failed: lower bound {lower:.1%} < {args.min_lower_bound:.1%}",
            file=sys.stderr,
        )
        return 1
    print(f"[proofrun] gate passed: lower bound {lower:.1%} >= {args.min_lower_bound:.1%}")
    return 0


def _control(args) -> int:
    from dspy_security_bench.policy import ToolPolicy
    from dspy_security_bench.procurement.control_registry import (
        create_control_submission_bundle,
        render_control_evidence_card_svg,
    )
    from dspy_security_bench.procurement.repeat_control import (
        render_repeat_control_terminal,
        run_repeat_control_twin,
    )

    if args.trials < 2:
        print("[proofrun] --trials must be at least 2", file=sys.stderr)
        return 2
    if not 0 < args.confidence < 1:
        print("[proofrun] --confidence must be between 0 and 1", file=sys.stderr)
        return 2
    bounds = {
        "containment": args.min_containment_lower_bound,
        "controlled harm-free": args.min_controlled_harm_free_lower_bound,
        "clean preservation": args.min_clean_preservation_lower_bound,
        "controlled resistance": args.min_controlled_resistance_lower_bound,
    }
    if any(not 0 <= value <= 1 for value in bounds.values()):
        print("[proofrun] lower-bound gates must be between 0 and 1", file=sys.stderr)
        return 2
    if not 0 <= args.max_unstable_pairs <= 5:
        print("[proofrun] --max-unstable-pairs must be between 0 and 5", file=sys.stderr)
        return 2
    try:
        factory = _agent_factory(args)
        policy = ToolPolicy.load(args.policy)
        approval_handler = (
            _resolve_callable(args.approval_handler) if args.approval_handler else None
        )
        report = run_repeat_control_twin(
            factory,
            policy,
            trials=args.trials,
            confidence_level=args.confidence,
            approval_handler=approval_handler,
            approval_handler_label=args.approval_handler,
            capture_arguments=args.capture_arguments,
            progress=lambda current, total: print(
                f"[proofrun] completed control trial {current}/{total}", file=sys.stderr
            ),
        )
        bundle = create_control_submission_bundle(
            report.to_dict(),
            submitter=args.submitter,
            agent_source_url=args.agent_source,
            policy_source_url=args.policy_source,
            notes=args.notes,
            provenance=capture_provenance(),
        )
        _write_json(Path(args.out), bundle)
        if args.report_out:
            _write_json(Path(args.report_out), report.to_dict())
        if args.card_out:
            card_path = Path(args.card_out)
            card_path.parent.mkdir(parents=True, exist_ok=True)
            card_path.write_text(render_control_evidence_card_svg(bundle))
    except Exception as exc:
        print(f"[proofrun] control failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    print(render_repeat_control_terminal(report))
    print(f"\n[proofrun] wrote {args.out}")
    print(f"[proofrun] bundle sha256: {bundle['bundle_sha256']}")
    print(
        "[proofrun] evidence tier before signature verification: "
        f"{bundle['submission']['attestation']}"
    )
    failures = []
    estimates = {
        "containment": report.summary.harm_containment_efficacy,
        "controlled harm-free": report.summary.controlled_harm_free,
        "clean preservation": report.summary.clean_utility_preservation,
        "controlled resistance": report.summary.controlled_attack_resistance,
    }
    for label, threshold in bounds.items():
        if threshold == 0:
            continue
        estimate = estimates[label]
        if estimate is None:
            failures.append(f"{label} lower bound is not estimable")
        elif estimate.lower < threshold:
            failures.append(f"{label} lower bound {estimate.lower:.1%} < {threshold:.1%}")
    if report.summary.unstable_pairs > args.max_unstable_pairs:
        failures.append(
            f"unstable pairs {report.summary.unstable_pairs} > {args.max_unstable_pairs}"
        )
    if failures:
        print(f"[proofrun] control gate failed: {'; '.join(failures)}", file=sys.stderr)
        return 1
    print("[proofrun] control gate passed")
    return 0


def _verify(args) -> int:
    path = Path(args.bundle)
    try:
        bundle = json.loads(path.read_text())
        bundle_type = bundle.get("bundle_type")
        if bundle_type == "dspy-security-bench-control-evidence-submission":
            from dspy_security_bench.procurement.control_registry import (
                verify_control_submission_bundle,
            )

            integrity = verify_control_submission_bundle(bundle, minimum_trials=args.minimum_trials)
            eligible = integrity.registry_eligible
            eligibility_label = "Control registry eligibility"
        else:
            from dspy_security_bench.procurement.repeat import verify_submission_bundle

            integrity = verify_submission_bundle(bundle, minimum_trials=args.minimum_trials)
            eligible = integrity.community_eligible
            eligibility_label = "Leaderboard eligibility"
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[INVALID] {path}: {exc}", file=sys.stderr)
        return 2

    print(f"Integrity: {'valid' if integrity.valid else 'INVALID'}")
    print(f"{eligibility_label}: {'yes' if eligible else 'no'}")
    print(f"Offline evidence tier: {integrity.evidence_tier}")
    for error in integrity.errors:
        print(f"  error: {error}")
    for warning in integrity.warnings:
        print(f"  note: {warning}")
    if not integrity.valid or not eligible:
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

    return lambda: LiteLLMFunctionCallingAgent(args.agent_model, name=args.name or args.agent_model)


def _resolve_callable(reference: str):
    module_name, separator, attribute = reference.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError(f"callable must be module:callable, got {reference!r}")
    callback = getattr(importlib.import_module(module_name), attribute)
    if not callable(callback):
        raise ValueError(f"{reference!r} does not resolve to a callable")
    return callback


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
