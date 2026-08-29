"""CollectiveGuard command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.collective.proof import (
    BUILT_IN_PROFILES,
    MAX_SCENARIO_BYTES,
    analyze_scenario,
    built_in_scenario,
    protocol_payload,
    validate_scenario,
    verify_collective_report,
)
from dspy_security_bench.collective.sarif import collective_report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench collective",
        description=(
            "Analyze content-free structural evidence for cross-run coordination, containment, "
            "safe-stop, evaluator integrity, and incident response."
        ),
    )
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen CollectiveGuard protocol")
    describe.add_argument("--json", action="store_true", dest="as_json")
    demo = commands.add_parser("demo", help="analyze all synthetic reference profiles")
    demo.add_argument("--json", action="store_true", dest="as_json")
    demo.add_argument("--out-dir", help="write recomputable JSON and SARIF reports")
    init = commands.add_parser("init", help="write a data-only starter scenario")
    init.add_argument("--profile", choices=tuple(BUILT_IN_PROFILES), default="hardened-collective")
    init.add_argument("--out", required=True)
    init.add_argument("--force", action="store_true")
    run = commands.add_parser("run", help="analyze one structural scenario")
    run.add_argument("path")
    run.add_argument("--json-out")
    run.add_argument("--sarif-out")
    run.add_argument("--fail-on-findings", action="store_true")
    run.add_argument("--require-timely-containment", action="store_true")
    verify = commands.add_parser("verify", help="recompute and verify a report offline")
    verify.add_argument("path")

    plane = commands.add_parser(
        "plane", help="run the provenance-aware CollectiveGuard v2 evidence plane"
    )
    plane_commands = plane.add_subparsers(dest="plane_command")
    plane_describe = plane_commands.add_parser("describe", help="show the v2 composition contract")
    plane_describe.add_argument("--json", action="store_true", dest="as_json")
    plane_demo = plane_commands.add_parser(
        "demo", help="run complete, partial, and violation fixtures"
    )
    plane_demo.add_argument("--json", action="store_true", dest="as_json")
    plane_demo.add_argument("--out-dir")
    plane_init = plane_commands.add_parser("init", help="write a v2 starter scenario")
    plane_init.add_argument(
        "--profile",
        choices=("hardened-complete", "hardened-partial", "emergent-complete"),
        default="hardened-complete",
    )
    plane_init.add_argument("--out", required=True)
    plane_init.add_argument("--force", action="store_true")
    plane_run = plane_commands.add_parser("run", help="analyze a v2 scenario")
    plane_run.add_argument("path")
    plane_run.add_argument("--json-out")
    plane_run.add_argument("--fail-on-findings", action="store_true")
    plane_run.add_argument("--fail-on-insufficient", action="store_true")
    plane_verify = plane_commands.add_parser("verify", help="verify a v2 report or registry bundle")
    plane_verify.add_argument("path")
    plane_bundle = plane_commands.add_parser("bundle", help="build a public registry submission")
    plane_bundle.add_argument("scenario")
    plane_bundle.add_argument("--out", required=True)
    plane_bundle.add_argument("--submitter", required=True)
    plane_bundle.add_argument("--runtime", required=True)
    plane_bundle.add_argument("--source-repository", required=True)
    plane_bundle.add_argument("--deployment-class", required=True)
    plane_bundle.add_argument("--known-gap", action="append", dest="known_gaps")

    bridge = commands.add_parser("bridge", help="map source manifests into the v2 evidence plane")
    bridge_commands = bridge.add_subparsers(dest="bridge_command")
    bridge_list = bridge_commands.add_parser("list", help="show EvidenceBridge contracts")
    bridge_list.add_argument("--json", action="store_true", dest="as_json")
    bridge_from = bridge_commands.add_parser("from-v2", help="create a reviewable bridge manifest")
    bridge_from.add_argument("scenario")
    bridge_from.add_argument("--adapter-profile", default="runtime-neutral-json")
    bridge_from.add_argument("--out", required=True)
    bridge_build = bridge_commands.add_parser(
        "build", help="validate a bridge manifest and emit v2"
    )
    bridge_build.add_argument("manifest")
    bridge_build.add_argument("--out", required=True)

    profile = commands.add_parser(
        "profile", help="apply federal, sector, and lab adoption profiles"
    )
    profile_commands = profile.add_subparsers(dest="profile_command")
    profile_commands.add_parser("list", help="list frozen adoption profiles")
    profile_show = profile_commands.add_parser("show", help="show one frozen adoption profile")
    profile_show.add_argument("profile_id")
    profile_show.add_argument("--json", action="store_true", dest="as_json")
    profile_assess = profile_commands.add_parser("assess", help="assess a v2 report")
    profile_assess.add_argument("report")
    profile_assess.add_argument("--profile", required=True, dest="profile_id")
    profile_assess.add_argument("--out", required=True)
    profile_assess.add_argument("--oscal-out")
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "plane":
        return _plane(args)
    if args.command == "bridge":
        return _bridge(args)
    if args.command == "profile":
        return _profile(args)
    if args.command == "describe":
        payload = protocol_payload()
        if args.as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("CollectiveGuard v1 — autonomous-agent collective containment assurance")
            print(f"Protocol sha256: {canonical_sha256(payload)}")
            print("Structural rules:")
            for rule_id, rule in payload["rules"].items():
                print(f"  - {rule_id} [{rule['severity']}]: {rule['title']}")
            print(payload["claim_boundary"])
        return 0
    if args.command == "init":
        destination = Path(args.out)
        if destination.exists() and not args.force:
            print(
                f"[collective] kept existing {destination} (use --force to replace)",
                file=sys.stderr,
            )
            return 2
        try:
            _write_json(destination, built_in_scenario(args.profile))
        except OSError as exc:
            print(f"[collective] init failed: {exc}", file=sys.stderr)
            return 2
        print(f"[collective] wrote {destination}")
        return 0
    if args.command == "verify":
        try:
            payload = _read_json(Path(args.path))
            errors = verify_collective_report(payload)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors = (str(exc),)
        if errors:
            print("[collective] verification failed: " + "; ".join(errors), file=sys.stderr)
            return 1
        print(f"[collective] verified {args.path}")
        return 0
    if args.command == "demo":
        reports = [analyze_scenario(built_in_scenario(name)) for name in BUILT_IN_PROFILES]
        if args.out_dir:
            directory = Path(args.out_dir)
            try:
                for report in reports:
                    stem = report["scenario"]["scenario_id"]
                    _write_json(directory / f"{stem}.report.json", report)
                    _write_json(
                        directory / f"{stem}.sarif.json", collective_report_to_sarif(report)
                    )
            except OSError as exc:
                print(f"[collective] demo failed: {exc}", file=sys.stderr)
                return 2
        if args.as_json:
            print(json.dumps(reports, indent=2, sort_keys=True))
        else:
            for report in reports:
                summary = report["summary"]
                print(
                    f"{report['scenario']['scenario_id']}: {summary['status']} · "
                    f"{summary['critical_findings']} critical / {summary['high_findings']} high · "
                    f"containment={summary['containment_status']}"
                )
            print(
                "No violation observed means no violation appears in the supplied structural record."
            )
        return 0

    try:
        scenario = _read_json(Path(args.path))
        scenario_errors = validate_scenario(scenario)
        if scenario_errors:
            raise ValueError("; ".join(scenario_errors))
        report = analyze_scenario(scenario)
        if args.json_out:
            _write_json(Path(args.json_out), report)
            print(f"[collective] wrote {args.json_out}")
        if args.sarif_out:
            _write_json(Path(args.sarif_out), collective_report_to_sarif(report))
            print(f"[collective] wrote {args.sarif_out}")
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[collective] run failed: {exc}", file=sys.stderr)
        return 2
    summary = report["summary"]
    print(
        f"[collective] {summary['status']}: {summary['finding_count']} findings; "
        f"containment={summary['containment_status']}; content_fields=0"
    )
    gate_failed = (args.fail_on_findings and summary["finding_count"] > 0) or (
        args.require_timely_containment
        and summary["containment_status"] not in {"timely", "not_observed"}
    )
    return 1 if gate_failed else 0


def _plane(args: argparse.Namespace) -> int:
    from dspy_security_bench.collective.registry import (
        BUNDLE_TYPE,
        build_collective_submission_bundle,
        verify_collective_submission_bundle,
    )
    from dspy_security_bench.collective.v2 import (
        BUILT_IN_PROFILES as V2_PROFILES,
    )
    from dspy_security_bench.collective.v2 import (
        analyze_scenario_v2,
        built_in_scenario_v2,
        verify_report,
    )
    from dspy_security_bench.collective.v2 import (
        protocol_payload as v2_protocol_payload,
    )
    from dspy_security_bench.collective.v2 import (
        protocol_sha256 as v2_protocol_sha256,
    )

    if args.plane_command is None:
        print("Usage: dspy-security-bench collective plane <describe|demo|init|run|verify|bundle>")
        return 0
    try:
        if args.plane_command == "describe":
            payload = v2_protocol_payload()
            if args.as_json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print("CollectiveGuard v2 — provenance-aware collective containment assurance")
                print(f"Protocol sha256: {v2_protocol_sha256()}")
                print(
                    "Outcomes: no violation observed · violations detected · insufficient evidence"
                )
                print(payload["claim_boundary"])
            return 0
        if args.plane_command == "demo":
            reports = [analyze_scenario_v2(built_in_scenario_v2(name)) for name in V2_PROFILES]
            if args.out_dir:
                root = Path(args.out_dir)
                for report in reports:
                    _write_json(root / f"{report['scenario']['scenario_id']}.report.json", report)
            if args.as_json:
                print(json.dumps(reports, indent=2, sort_keys=True))
            else:
                for report in reports:
                    summary = report["summary"]
                    print(
                        f"{report['scenario']['scenario_id']}: {summary['status']} · "
                        f"{summary['finding_count']} findings · "
                        f"evidence_complete={summary['clean_evidence_complete']}"
                    )
            return 0
        if args.plane_command == "init":
            destination = Path(args.out)
            if destination.exists() and not args.force:
                print(
                    f"[collective] kept existing {destination} (use --force to replace)",
                    file=sys.stderr,
                )
                return 2
            _write_json(destination, built_in_scenario_v2(args.profile))
            print(f"[collective] wrote {destination}")
            return 0
        if args.plane_command == "run":
            report = analyze_scenario_v2(_read_json(Path(args.path)))
            if args.json_out:
                _write_json(Path(args.json_out), report)
                print(f"[collective] wrote {args.json_out}")
            status = report["summary"]["status"]
            print(
                f"[collective] {status}: {report['summary']['finding_count']} findings; "
                f"sources_complete={report['summary']['required_sources_complete']}"
            )
            return (
                1
                if (
                    (args.fail_on_findings and report["summary"]["finding_count"])
                    or (args.fail_on_insufficient and status == "insufficient_evidence")
                )
                else 0
            )
        if args.plane_command == "verify":
            payload = _read_json(Path(args.path))
            if payload.get("bundle_type") == BUNDLE_TYPE:
                result = verify_collective_submission_bundle(payload)
                errors = result.errors
                for warning in result.warnings:
                    print(f"  note: {warning}")
            else:
                errors = verify_report(payload)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[collective] verified {args.path}")
            return 0
        scenario = _read_json(Path(args.scenario))
        bundle = build_collective_submission_bundle(
            scenario,
            submitter=args.submitter,
            runtime=args.runtime,
            source_repository=args.source_repository,
            deployment_class=args.deployment_class,
            known_gaps=args.known_gaps,
        )
        _write_json(Path(args.out), bundle)
        print(f"[collective] wrote registry bundle {args.out}")
        print(f"Bundle sha256: {bundle['bundle_sha256']}")
        return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[collective] v2 failed: {exc}", file=sys.stderr)
        return 2


def _bridge(args: argparse.Namespace) -> int:
    from dspy_security_bench.collective.bridge import (
        ADAPTER_PROFILES,
        bridge_contract,
        bridge_manifest_from_v2,
        build_v2_scenario,
    )

    if args.bridge_command is None:
        print("Usage: dspy-security-bench collective bridge <list|from-v2|build>")
        return 0
    try:
        if args.bridge_command == "list":
            payload = bridge_contract()
            if args.as_json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                for key, item in ADAPTER_PROFILES.items():
                    print(f"{key:26} {item['maturity']:16} {item['interface']}")
                print(payload["claim_boundary"])
            return 0
        if args.bridge_command == "from-v2":
            manifest = bridge_manifest_from_v2(
                _read_json(Path(args.scenario)), adapter_profile=args.adapter_profile
            )
            _write_json(Path(args.out), manifest)
            print(f"[collective] wrote EvidenceBridge manifest {args.out}")
            return 0
        scenario = build_v2_scenario(_read_json(Path(args.manifest)))
        _write_json(Path(args.out), scenario)
        print(f"[collective] wrote CollectiveGuard v2 scenario {args.out}")
        return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[collective] bridge failed: {exc}", file=sys.stderr)
        return 2


def _profile(args: argparse.Namespace) -> int:
    from dspy_security_bench.collective.profiles import (
        PROFILES,
        assess_profile,
        built_in_profile,
        export_oscal,
    )

    if args.profile_command is None:
        print("Usage: dspy-security-bench collective profile <list|show|assess>")
        return 0
    try:
        if args.profile_command == "list":
            for key, profile in PROFILES.items():
                print(f"{key:24} {profile['title']}")
            return 0
        if args.profile_command == "show":
            profile = built_in_profile(args.profile_id)
            if args.as_json:
                print(json.dumps(profile, indent=2, sort_keys=True))
            else:
                print(f"{profile['title']} ({profile['profile_id']})")
                print(profile["deployment_context"])
                print("Required sources: " + ", ".join(profile["required_source_types"]))
                print(profile["claim_boundary"])
            return 0
        report = _read_json(Path(args.report))
        assessment = assess_profile(report, built_in_profile(args.profile_id))
        _write_json(Path(args.out), assessment)
        if args.oscal_out:
            _write_json(Path(args.oscal_out), export_oscal(assessment))
        print(f"[collective] {assessment['summary']['status']}: wrote {args.out}")
        return 1 if assessment["summary"]["status"] == "review_required" else 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[collective] profile failed: {exc}", file=sys.stderr)
        return 2


def _read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_SCENARIO_BYTES:
        raise ValueError("CollectiveGuard JSON input exceeds the 1 MiB boundary")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
