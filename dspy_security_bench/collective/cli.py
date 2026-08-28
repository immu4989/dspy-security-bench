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
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0
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
