"""CLI for attested RepeatTwin execution envelopes."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.proofrun import capture_provenance
from dspy_security_bench.proofrun_review import ReviewPolicy, render_review, review_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench proofrun",
        description=(
            "Create evidence bundles, review repeated-trial or structural evidence, "
            "and prepare, compare, snapshot, or practice owner-controlled collection handoffs."
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

    incident = commands.add_parser(
        "incident", help="run repeated IncidentTwin and emit attestation-ready evidence"
    )
    incident_target = incident.add_mutually_exclusive_group(required=True)
    incident_target.add_argument("--agent", help="module:callable returning an Agent")
    incident_target.add_argument("--agent-model", help="LiteLLM model id for the built-in agent")
    incident.add_argument("--name", help="display name override for --agent-model")
    incident.add_argument("--trials", type=int, default=10)
    incident.add_argument("--confidence", type=float, default=0.95)
    incident.add_argument("--min-lower-bound", type=float, default=0.0)
    incident.add_argument("--out", required=True, help="destination bundle JSON")
    incident.add_argument("--report-out", help="optional standalone RepeatIncidentTwin JSON")
    incident.add_argument("--submitter", required=True)
    incident.add_argument("--agent-source", required=True)
    incident.add_argument("--notes", default="")

    source = commands.add_parser(
        "source", help="run repeated SourceTwin or a custom MissionPack and emit evidence"
    )
    source_target = source.add_mutually_exclusive_group(required=True)
    source_target.add_argument("--agent", help="module:callable returning an Agent")
    source_target.add_argument("--agent-model", help="LiteLLM model id for the built-in agent")
    source.add_argument("--name", help="display name override for --agent-model")
    source.add_argument("--pack", default="source-twin", help="built-in alias or local YAML/JSON")
    source.add_argument("--trials", type=int, default=10)
    source.add_argument("--confidence", type=float, default=0.95)
    source.add_argument("--min-lower-bound", type=float, default=0.0)
    source.add_argument("--out", required=True, help="destination bundle JSON")
    source.add_argument("--report-out", help="optional standalone repeated report JSON")
    source.add_argument("--submitter", required=True)
    source.add_argument("--agent-source", required=True)
    source.add_argument("--notes", default="")

    authority = commands.add_parser(
        "authority",
        help="run repeated delegated-authorization conformance and emit evidence",
    )
    authority_target = authority.add_mutually_exclusive_group(required=True)
    authority_target.add_argument("--adapter", help="module:callable returning an AuthorityAdapter")
    authority_target.add_argument(
        "--reference", choices=("bounded", "ambient"), help="zero-cost reference fixture"
    )
    authority.add_argument("--trials", type=int, default=10)
    authority.add_argument("--confidence", type=float, default=0.95)
    authority.add_argument("--min-lower-bound", type=float, default=0.0)
    authority.add_argument("--out", required=True, help="destination bundle JSON")
    authority.add_argument("--report-out", help="optional standalone repeated report JSON")
    authority.add_argument("--submitter", required=True)
    authority.add_argument("--adapter-source", required=True)
    authority.add_argument("--notes", default="")

    verify = commands.add_parser("verify", help="recompute a bundle and verify GitHub provenance")
    verify.add_argument("bundle")
    output_format = verify.add_mutually_exclusive_group()
    output_format.add_argument("--json", action="store_true", help="emit one source-redacted machine-readable review decision")
    output_format.add_argument("--junit", action="store_true", help="emit source-redacted JUnit XML for CI; preserve the native exit code")
    output_format.add_argument("--html", action="store_true", help="emit a self-contained source-redacted HTML review; preserve the native exit code")
    output_format.add_argument("--report-dir", help="new directory for JSON, HTML, JUnit and a byte manifest from one review; stdout is an export receipt")
    verify.add_argument("--attestation-repo", help="owner/repository; defaults to bundle metadata")
    review_kind = verify.add_mutually_exclusive_group()
    # Older argparse versions identify explicit mutually-exclusive values by
    # identity against the default. Defer the numeric default so an explicit 5
    # cannot disappear from conflict detection through small-integer interning.
    review_kind.add_argument("--minimum-trials", type=int, default=None, help="minimum repeated trials (default: 5)")
    review_kind.add_argument("--structural", action="store_true", help="explicit structural review; no trial-confidence or execution-authentication claim")
    verify.add_argument("--expected-file-sha256", help="independent SHA-256 pin for exact input bytes")
    verify.add_argument(
        "--offline", action="store_true", help="skip cryptographic provenance lookup"
    )
    verify.add_argument("--require-trusted-builder", action="store_true")
    verify.add_argument(
        "--allow-self-hosted-runner",
        action="store_true",
        help="accept GitHub attestations produced on self-hosted runners",
    )
    collection = commands.add_parser("verify-collection", help="review every required entry in an owner-controlled evidence plan")
    collection.add_argument("plan", help="local JSON plan; referenced files must be beneath its directory")
    collection.add_argument("--expected-plan-file-sha256", help="independent SHA-256 pin for exact plan bytes")
    collection_format = collection.add_mutually_exclusive_group()
    collection_format.add_argument("--json", action="store_true", help="emit one source-redacted collection decision")
    collection_format.add_argument("--junit", action="store_true", help="emit one JUnit testcase per required entry, or an invalid-plan error")
    collection_format.add_argument("--html", action="store_true", help="emit a self-contained source-redacted HTML collection review")
    collection_format.add_argument("--report-dir", help="new directory for all report formats from one review; stdout is an export receipt")
    comparison = commands.add_parser("compare-plans", help="compare collection requirements against an independently pinned baseline")
    comparison.add_argument("baseline", help="owner-approved local collection plan")
    comparison.add_argument("candidate", help="proposed local collection plan")
    comparison.add_argument("--expected-baseline-file-sha256", required=True, help="independently retained baseline SHA-256")
    comparison.add_argument("--json", action="store_true", help="emit one source-redacted plan comparison")
    preparation = commands.add_parser("prepare-plan", help="record artifact byte pins for explicit owner requirements; does not approve or verify evidence")
    preparation.add_argument("requirements", help="strict local JSON requirements with explicit slots and policies")
    preparation.add_argument("--out", required=True, help="new draft .json file beside the requirements; never overwritten")
    preparation.add_argument("--expected-requirements-file-sha256", help="independently retained requirements SHA-256")
    preparation.add_argument("--json", action="store_true", help="emit a source-redacted preparation receipt, not draft contents")
    snapshot = commands.add_parser("snapshot-collection", help="copy exact pinned collection bytes for recipient review; full-content local output, no upload")
    snapshot.add_argument("plan", help="owner-controlled local collection plan")
    snapshot.add_argument("--out", required=True, help="new transfer directory under an existing unlinked parent; never overwritten")
    snapshot.add_argument("--expected-plan-file-sha256", required=True, help="independently retained plan SHA-256")
    snapshot.add_argument("--json", action="store_true", help="emit a source-redacted receipt, not the snapshot contents")
    demo = commands.add_parser("collection-demo", help="model-free synthetic handoff walkthrough with pass, unmet, and missing-evidence cases")
    demo.add_argument("--out", required=True, help="new local demonstration directory under an existing unlinked parent")
    demo.add_argument("--json", action="store_true", help="emit observed demo outcomes, not a deployment approval")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command in {"run", "control", "incident", "source", "authority"}:
        try:
            _preflight_outputs(args)
        except (OSError, ValueError):
            print("[proofrun] output preflight failed: use distinct new files under existing directories; "
                  "symlinks and existing files are not allowed", file=sys.stderr)
            return 2
    if args.command == "run":
        return _run(args)
    if args.command == "control":
        return _control(args)
    if args.command == "incident":
        return _incident(args)
    if args.command == "source":
        return _source(args)
    if args.command == "authority":
        return _authority(args)
    if args.command == "verify":
        return _verify(args)
    if args.command == "verify-collection":
        from dspy_security_bench.proofrun_collection import render_collection, review_collection

        if args.report_dir is not None:
            from dspy_security_bench.proofrun_reports import export_collection_reports

            receipt = export_collection_reports(Path(args.plan), Path(args.report_dir),
                                                expected_plan_file_sha256=args.expected_plan_file_sha256)
            print(json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False))
            return receipt["exit_code"]
        result = review_collection(Path(args.plan), expected_plan_file_sha256=args.expected_plan_file_sha256)
        if args.json:
            print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        elif args.junit:
            from dspy_security_bench.proofrun_junit import render_collection_junit

            print(render_collection_junit(result, scope=args.plan))
        elif args.html:
            from dspy_security_bench.proofrun_html import render_collection_html

            print(render_collection_html(result))
        else:
            print(render_collection(result), file=sys.stderr if result["exit_code"] == 2 else sys.stdout)
        return result["exit_code"]
    if args.command == "compare-plans":
        from dspy_security_bench.proofrun_plan_diff import compare_plans, render_plan_comparison

        result = compare_plans(Path(args.baseline), Path(args.candidate),
                               expected_baseline_file_sha256=args.expected_baseline_file_sha256)
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False) if args.json else render_plan_comparison(result),
              file=sys.stderr if result["exit_code"] == 2 and not args.json else sys.stdout)
        return result["exit_code"]
    if args.command == "prepare-plan":
        from dspy_security_bench.proofrun_prepare import prepare_plan_file, render_preparation

        result = prepare_plan_file(Path(args.requirements), Path(args.out),
                                   expected_requirements_file_sha256=args.expected_requirements_file_sha256)
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False) if args.json else render_preparation(result),
              file=sys.stderr if result["exit_code"] == 2 and not args.json else sys.stdout)
        return result["exit_code"]
    if args.command == "snapshot-collection":
        from dspy_security_bench.proofrun_snapshot import render_snapshot, snapshot_collection

        result = snapshot_collection(Path(args.plan), Path(args.out), expected_plan_file_sha256=args.expected_plan_file_sha256)
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False) if args.json else render_snapshot(result),
              file=sys.stderr if result["exit_code"] == 2 and not args.json else sys.stdout)
        return result["exit_code"]
    if args.command == "collection-demo":
        from dspy_security_bench.proofrun_demo import DISCLAIMER, create_collection_demo

        result = create_collection_demo(Path(args.out))
        if args.json:
            print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        elif result["exit_code"] == 0:
            print("Synthetic handoff walkthrough created. Open README.md in the output directory.")
            print("Observed native exits: complete=0, provenance-required=1, missing-evidence=2.")
            print(DISCLAIMER)
        else:
            print(f"Collection demo failed: {result['reason_code']}. Inspect any partial new output and retry in a fresh directory.", file=sys.stderr)
        return result["exit_code"]
    return 2


def _run(args) -> int:
    from dspy_security_bench.procurement.repeat import (
        create_submission_bundle,
        render_repeat_terminal,
        run_repeat_twin,
    )
    from dspy_security_bench.procurement.submission_metadata import prepare_submission_metadata

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
        metadata = prepare_submission_metadata(
            submitter=args.submitter, agent_source_url=args.agent_source,
            notes=args.notes, provenance=capture_provenance(),
        )
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
            provenance=metadata["provenance"],
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
    from dspy_security_bench.procurement.submission_metadata import prepare_submission_metadata

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
        metadata = prepare_submission_metadata(
            submitter=args.submitter, agent_source_url=args.agent_source,
            notes=args.notes, provenance=capture_provenance(),
            control=True, policy_source_url=args.policy_source,
        )
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
            provenance=metadata["provenance"],
        )
        _write_json(Path(args.out), bundle)
        if args.report_out:
            _write_json(Path(args.report_out), report.to_dict())
        if args.card_out:
            card_path = Path(args.card_out)
            _write_text(card_path, render_control_evidence_card_svg(bundle))
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


def _incident(args) -> int:
    from dspy_security_bench.incident.repeat import (
        create_incident_submission_bundle,
        run_repeat_incident_twin,
    )
    from dspy_security_bench.procurement.submission_metadata import prepare_submission_metadata

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
        metadata = prepare_submission_metadata(
            submitter=args.submitter, agent_source_url=args.agent_source,
            notes=args.notes, provenance=capture_provenance(),
            source_field="agent_source_url",
        )
        report = run_repeat_incident_twin(
            _agent_factory(args),
            trials=args.trials,
            confidence_level=args.confidence,
            progress=lambda current, total: print(
                f"[proofrun] completed incident trial {current}/{total}", file=sys.stderr
            ),
        )
        bundle = create_incident_submission_bundle(
            report.to_dict(),
            submitter=args.submitter,
            agent_source_url=args.agent_source,
            notes=args.notes,
            provenance=metadata["provenance"],
        )
        _write_json(Path(args.out), bundle)
        if args.report_out:
            _write_json(Path(args.report_out), report.to_dict())
    except Exception as exc:
        print(f"[proofrun] incident failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    estimate = report.summary.attack_resistance
    print(f"IncidentTwin repeated — {report.agent}")
    print(
        f"attack resistance: {estimate.rate:.1%} "
        f"({args.confidence:.0%} Wilson {estimate.lower:.1%}–{estimate.upper:.1%})"
    )
    print(f"[proofrun] wrote {args.out}")
    print(f"[proofrun] bundle sha256: {bundle['bundle_sha256']}")
    if estimate.lower < args.min_lower_bound:
        print(
            f"[proofrun] gate failed: lower bound {estimate.lower:.1%} "
            f"< {args.min_lower_bound:.1%}",
            file=sys.stderr,
        )
        return 1
    print(f"[proofrun] gate passed: lower bound {estimate.lower:.1%} >= {args.min_lower_bound:.1%}")
    return 0


def _source(args) -> int:
    from dspy_security_bench.mission.loader import load_mission_pack
    from dspy_security_bench.mission.repeat import (
        create_source_submission_bundle,
        run_repeat_mission_pack,
    )
    from dspy_security_bench.procurement.submission_metadata import prepare_submission_metadata

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
        metadata = prepare_submission_metadata(
            submitter=args.submitter, agent_source_url=args.agent_source,
            notes=args.notes, provenance=capture_provenance(),
            source_field="agent_source_url",
        )
        pack = load_mission_pack(args.pack)
        report = run_repeat_mission_pack(
            _agent_factory(args),
            pack,
            trials=args.trials,
            confidence_level=args.confidence,
            progress=lambda current, total: print(
                f"[proofrun] completed source trial {current}/{total}", file=sys.stderr
            ),
        )
        bundle = create_source_submission_bundle(
            report.to_dict(),
            submitter=args.submitter,
            agent_source_url=args.agent_source,
            notes=args.notes,
            provenance=metadata["provenance"],
        )
        _write_json(Path(args.out), bundle)
        if args.report_out:
            _write_json(Path(args.report_out), report.to_dict())
    except Exception as exc:
        print(f"[proofrun] source failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    estimate = report.summary.attack_resistance
    print(f"MissionForge / {report.pack_id} repeated — {report.agent}")
    print(
        f"attack resistance: {estimate.rate:.1%} "
        f"({args.confidence:.0%} Wilson {estimate.lower:.1%}–{estimate.upper:.1%})"
    )
    print(f"[proofrun] wrote {args.out}")
    print(f"[proofrun] bundle sha256: {bundle['bundle_sha256']}")
    if estimate.lower < args.min_lower_bound:
        print(
            f"[proofrun] gate failed: lower bound {estimate.lower:.1%} "
            f"< {args.min_lower_bound:.1%}",
            file=sys.stderr,
        )
        return 1
    print(f"[proofrun] gate passed: lower bound {estimate.lower:.1%} >= {args.min_lower_bound:.1%}")
    return 0


def _authority(args) -> int:
    from dspy_security_bench.authority.repeat import (
        create_authority_submission_bundle,
        run_repeat_authority_twin,
    )
    from dspy_security_bench.procurement.submission_metadata import prepare_submission_metadata

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
        metadata = prepare_submission_metadata(
            submitter=args.submitter, agent_source_url=args.adapter_source,
            notes=args.notes, provenance=capture_provenance(),
            source_field="adapter_source_url",
        )
        report = run_repeat_authority_twin(
            _authority_adapter_factory(args),
            trials=args.trials,
            confidence_level=args.confidence,
            progress=lambda current, total: print(
                f"[proofrun] completed authority trial {current}/{total}", file=sys.stderr
            ),
        )
        bundle = create_authority_submission_bundle(
            report.to_dict(),
            submitter=args.submitter,
            adapter_source_url=args.adapter_source,
            notes=args.notes,
            provenance=metadata["provenance"],
        )
        _write_json(Path(args.out), bundle)
        if args.report_out:
            _write_json(Path(args.report_out), report.to_dict())
    except Exception as exc:
        print(f"[proofrun] authority failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    estimate = report.summary.attack_resistance
    print(f"AuthorityTwin repeated — {report.adapter}")
    print(
        f"attack resistance: {estimate.rate:.1%} "
        f"({args.confidence:.0%} Wilson {estimate.lower:.1%}–{estimate.upper:.1%})"
    )
    print(f"harm containment: {report.summary.harm_containment.rate:.1%}")
    print(f"receipt integrity: {report.summary.receipt_integrity.rate:.1%}")
    print(f"[proofrun] wrote {args.out}")
    print(f"[proofrun] bundle sha256: {bundle['bundle_sha256']}")
    if estimate.lower < args.min_lower_bound:
        print(
            f"[proofrun] gate failed: lower bound {estimate.lower:.1%} "
            f"< {args.min_lower_bound:.1%}",
            file=sys.stderr,
        )
        return 1
    print(f"[proofrun] gate passed: lower bound {estimate.lower:.1%} >= {args.min_lower_bound:.1%}")
    return 0


def _verify(args) -> int:
    minimum_trials = None if args.structural else (5 if args.minimum_trials is None else args.minimum_trials)
    policy = ReviewPolicy(
        minimum_trials=minimum_trials, offline=args.offline,
        expected_file_sha256=args.expected_file_sha256,
        attestation_repository=args.attestation_repo,
        require_trusted_builder=args.require_trusted_builder,
        allow_self_hosted_runner=args.allow_self_hosted_runner,
    )
    if args.report_dir is not None:
        from dspy_security_bench.proofrun_reports import export_bundle_reports

        receipt = export_bundle_reports(Path(args.bundle), Path(args.report_dir), policy=policy)
        print(json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False))
        return receipt["exit_code"]
    review = review_bundle(Path(args.bundle), policy=policy)
    if args.json:
        print(json.dumps(review, sort_keys=True, indent=2, allow_nan=False))
    elif args.junit:
        from dspy_security_bench.proofrun_junit import render_review_junit

        print(render_review_junit(review, scope=args.bundle))
    elif args.html:
        from dspy_security_bench.proofrun_html import render_review_html

        print(render_review_html(review))
    else:
        print(render_review(review), file=sys.stderr if review["exit_code"] == 2 else sys.stdout)
    return review["exit_code"]


def _agent_factory(args):
    if args.agent:
        module_name, separator, attribute = args.agent.partition(":")
        if not separator or not module_name or not attribute:
            raise ValueError(f"--agent must be module:callable, got {args.agent!r}")
        return getattr(importlib.import_module(module_name), attribute)
    from dspy_security_bench.agents import LiteLLMFunctionCallingAgent

    return lambda: LiteLLMFunctionCallingAgent(args.agent_model, name=args.name or args.agent_model)


def _authority_adapter_factory(args):
    if args.adapter:
        return _resolve_callable(args.adapter)
    from dspy_security_bench.authority.adapter import (
        build_ambient_authority_adapter,
        build_bounded_authority_adapter,
    )

    return (
        build_ambient_authority_adapter
        if args.reference == "ambient"
        else build_bounded_authority_adapter
    )


def _resolve_callable(reference: str):
    module_name, separator, attribute = reference.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError(f"callable must be module:callable, got {reference!r}")
    callback = getattr(importlib.import_module(module_name), attribute)
    if not callable(callback):
        raise ValueError(f"{reference!r} does not resolve to a callable")
    return callback


def _checked_output(path: Path) -> Path:
    """Validate an owner-selected destination without creating or replacing data."""
    absolute = Path(path.absolute())
    if any(parent.is_symlink() for parent in (absolute, *absolute.parents)):
        raise ValueError("output paths must not traverse symlinks")
    if absolute.exists() or not absolute.parent.is_dir():
        raise ValueError("outputs require new files in existing directories")
    return absolute.resolve()


def _preflight_outputs(args) -> None:
    """Fail before user factories, model calls, or evidence generation."""
    paths = [_checked_output(Path(value)) for value in (
        getattr(args, "out", None), getattr(args, "report_out", None), getattr(args, "card_out", None),
    ) if value is not None]
    if len(set(paths)) != len(paths):
        raise ValueError("output destinations must be distinct")


def _write_text(path: Path, content: str) -> None:
    # Recheck after execution and exclusively create: an output that appeared
    # since preflight must never be truncated. Multi-file writes are not atomic.
    _checked_output(path)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(content)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    content = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
    _write_text(path, content)
