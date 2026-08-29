"""DefenderTwin and Verified Cyber Defense Commons command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dspy_security_bench.defend.protocol import (
    BUILT_IN_MISSIONS,
    analyze_remediation,
    built_in_mission,
    built_in_proposal,
    protocol_payload,
    protocol_sha256,
    validate_mission,
    validate_proposal,
    verify_report,
)

MAX_INPUT_BYTES = 5_000_000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench defend",
        description=(
            "Prove whether a synthetic cyber-defense remediation closes known attack paths, "
            "preserves essential services, respects authorization, and remains rollback-capable."
        ),
    )
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen DefenderTwin protocol")
    describe.add_argument("--json", action="store_true", dest="as_json")
    commands.add_parser("missions", help="list packaged critical-service missions")
    init = commands.add_parser("init", help="write a packaged data-only mission")
    init.add_argument("--mission", choices=tuple(BUILT_IN_MISSIONS), default="community-hospital")
    init.add_argument("--out", required=True)
    init.add_argument("--force", action="store_true")
    proposal = commands.add_parser("proposal", help="write a deterministic reference proposal")
    proposal.add_argument("mission")
    proposal.add_argument(
        "--profile",
        choices=("bounded-reference", "disruptive-reference", "safe-stop-reference"),
        default="bounded-reference",
    )
    proposal.add_argument("--out", required=True)
    proposal.add_argument("--force", action="store_true")
    run = commands.add_parser("run", help="evaluate a proposal against a frozen mission")
    run.add_argument("mission")
    run.add_argument("proposal")
    run.add_argument("--json-out")
    run.add_argument("--sarif-out")
    run.add_argument("--oscal-out")
    run.add_argument("--fail-on-unsafe", action="store_true")
    run.add_argument("--fail-on-insufficient", action="store_true")
    verify = commands.add_parser("verify", help="recompute a report or evidence bundle offline")
    verify.add_argument("path")
    demo = commands.add_parser("demo", help="run bounded, disruptive, and safe-stop references")
    demo.add_argument("--mission", choices=tuple(BUILT_IN_MISSIONS))
    demo.add_argument("--out-dir")
    demo.add_argument("--json", action="store_true", dest="as_json")
    bundle = commands.add_parser("bundle", help="build a privacy-bounded registry bundle")
    bundle.add_argument("report")
    bundle.add_argument("--out", required=True)
    bundle.add_argument("--submitter", required=True)
    bundle.add_argument("--runtime", required=True)
    bundle.add_argument("--source-repository", required=True)
    bundle.add_argument("--deployment-class", required=True)
    bundle.add_argument(
        "--disclosure-status",
        choices=("public-pattern", "embargoed", "private"),
        default="public-pattern",
    )
    bundle.add_argument("--known-gap", action="append", dest="known_gaps")

    adapter = commands.add_parser("adapter", help="manage defender adapter contract evidence")
    adapter_commands = adapter.add_subparsers(dest="adapter_command")
    adapter_init = adapter_commands.add_parser("init", help="write an adapter manifest template")
    adapter_init.add_argument("--out", required=True)
    adapter_init.add_argument("--force", action="store_true")
    adapter_check = adapter_commands.add_parser("check", help="validate an adapter manifest")
    adapter_check.add_argument("manifest")
    adapter_test = adapter_commands.add_parser("test", help="test a manifest and frozen output")
    adapter_test.add_argument("manifest")
    adapter_test.add_argument("mission")
    adapter_test.add_argument("proposal")
    adapter_test.add_argument("--out")
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "describe":
            payload = protocol_payload()
            if args.as_json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print("DefenderTwin v1 — verified cyber-defense remediation assurance")
                print(f"Protocol sha256: {protocol_sha256()}")
                print(
                    "Outcomes: effective and safe · effective with regression · ineffective · insufficient evidence"
                )
                print(payload["claim_boundary"])
            return 0
        if args.command == "missions":
            for mission_id, description in BUILT_IN_MISSIONS.items():
                print(f"{mission_id}: {description}")
            return 0
        if args.command == "init":
            return _write_once(
                Path(args.out), built_in_mission(args.mission), args.force, "mission"
            )
        if args.command == "proposal":
            mission = _mission(args.mission)
            payload = built_in_proposal(mission, args.profile)
            return _write_once(Path(args.out), payload, args.force, "proposal")
        if args.command == "run":
            return _run(args)
        if args.command == "verify":
            return _verify(Path(args.path))
        if args.command == "demo":
            return _demo(args)
        if args.command == "bundle":
            return _bundle(args)
        if args.command == "adapter":
            return _adapter(args)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[defend] {args.command} failed: {exc}", file=sys.stderr)
        return 2
    return 0


def _run(args: argparse.Namespace) -> int:
    from dspy_security_bench.defend.oscal import report_to_oscal
    from dspy_security_bench.defend.sarif import report_to_sarif

    mission = _mission(args.mission)
    proposal = _read_json(Path(args.proposal))
    errors = validate_proposal(proposal, mission)
    if errors:
        raise ValueError("invalid proposal: " + "; ".join(errors))
    report = analyze_remediation(mission, proposal)
    if args.json_out:
        _write_json(Path(args.json_out), report)
        print(f"[defend] wrote {args.json_out}")
    if args.sarif_out:
        _write_json(Path(args.sarif_out), report_to_sarif(report))
        print(f"[defend] wrote {args.sarif_out}")
    if args.oscal_out:
        _write_json(Path(args.oscal_out), report_to_oscal(report))
        print(f"[defend] wrote {args.oscal_out}")
    summary = report["summary"]
    print(
        f"[defend] {summary['outcome']}: {summary['attack_paths_closed']}/"
        f"{summary['attack_path_count']} attack paths closed; "
        f"mission_stable={summary['mission_services_stable']}; "
        f"evidence_complete={summary['evidence_complete']}"
    )
    unsafe = summary["outcome"] in {"effective_with_regression", "ineffective"}
    insufficient = summary["outcome"] == "insufficient_evidence"
    return (
        1 if (args.fail_on_unsafe and unsafe) or (args.fail_on_insufficient and insufficient) else 0
    )


def _verify(path: Path) -> int:
    from dspy_security_bench.defend.evidence import BUNDLE_TYPE, verify_evidence_bundle

    payload = _read_json(path)
    if payload.get("bundle_type") == BUNDLE_TYPE:
        result = verify_evidence_bundle(payload)
        errors = result.errors
        warnings = result.warnings
    else:
        errors = verify_report(payload)
        warnings = ()
    if errors:
        print("[defend] verification failed: " + "; ".join(errors), file=sys.stderr)
        return 1
    print(f"[defend] verified {path}")
    for warning in warnings:
        print(f"[defend] review: {warning}")
    return 0


def _demo(args: argparse.Namespace) -> int:
    mission_names = [args.mission] if args.mission else list(BUILT_IN_MISSIONS)
    reports = []
    for mission_name in mission_names:
        mission = built_in_mission(mission_name)
        for profile in ("bounded-reference", "disruptive-reference", "safe-stop-reference"):
            report = analyze_remediation(mission, built_in_proposal(mission, profile))
            reports.append(report)
            if args.out_dir:
                _write_json(Path(args.out_dir) / f"{mission_name}-{profile}.report.json", report)
    if args.as_json:
        print(json.dumps(reports, indent=2, sort_keys=True))
    else:
        for report in reports:
            summary = report["summary"]
            print(
                f"{report['mission']['mission_id']} / {report['proposal']['proposal_id'].rsplit(':', 1)[-1]}: "
                f"{summary['outcome']} · {summary['attack_paths_closed']}/"
                f"{summary['attack_path_count']} paths · {summary['finding_count']} findings"
            )
        print(
            "Reference results are fictional synthetic fixtures, not product or deployment claims."
        )
    return 0


def _bundle(args: argparse.Namespace) -> int:
    from dspy_security_bench.defend.evidence import build_evidence_bundle

    report = _read_json(Path(args.report))
    bundle = build_evidence_bundle(
        report,
        submitter=args.submitter,
        runtime=args.runtime,
        source_repository=args.source_repository,
        deployment_class=args.deployment_class,
        disclosure_status=args.disclosure_status,
        known_gaps=args.known_gaps,
    )
    _write_json(Path(args.out), bundle)
    print(f"[defend] wrote {args.out}")
    print(f"[defend] bundle sha256: {bundle['bundle_sha256']}")
    return 0


def _adapter(args: argparse.Namespace) -> int:
    from dspy_security_bench.defend.conformance import (
        adapter_manifest_template,
        test_adapter,
        validate_adapter_manifest,
    )

    if args.adapter_command is None:
        print("Usage: dspy-security-bench defend adapter <init|check|test>")
        return 0
    if args.adapter_command == "init":
        return _write_once(
            Path(args.out), adapter_manifest_template(), args.force, "adapter manifest"
        )
    manifest = _read_json(Path(args.manifest))
    if args.adapter_command == "check":
        errors = validate_adapter_manifest(manifest)
        if errors:
            print("[defend] adapter check failed: " + "; ".join(errors), file=sys.stderr)
            return 1
        print(f"[defend] verified adapter manifest {args.manifest}")
        return 0
    mission = _mission(args.mission)
    proposal = _read_json(Path(args.proposal))
    report = test_adapter(manifest, mission, proposal)
    if args.out:
        _write_json(Path(args.out), report)
        print(f"[defend] wrote {args.out}")
    print(f"[defend] adapter {report['summary']['status']}")
    for error in report["errors"]:
        print(f"  - {error}")
    return 0 if report["summary"]["status"] == "conformant" else 1


def _mission(value: str) -> dict[str, Any]:
    if value in BUILT_IN_MISSIONS:
        return built_in_mission(value)
    payload = _read_json(Path(value))
    errors = validate_mission(payload)
    if errors:
        raise ValueError("invalid mission: " + "; ".join(errors))
    return payload


def _read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("input must be a JSON object")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_once(path: Path, payload: Any, force: bool, label: str) -> int:
    if path.exists() and not force:
        print(f"[defend] kept existing {path} (use --force to replace)", file=sys.stderr)
        return 2
    _write_json(path, payload)
    print(f"[defend] wrote {label} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
