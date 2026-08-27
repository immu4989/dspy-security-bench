"""ScheduleProof command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dspy_security_bench.schedule.proof import (
    BUILT_IN_PROFILES,
    MAX_SCENARIO_BYTES,
    analyze_scenario,
    built_in_scenario,
    protocol_payload,
    validate_scenario,
    verify_schedule_report,
)
from dspy_security_bench.schedule.sarif import schedule_report_to_sarif


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench schedule",
        description="Explore bounded authorization interleavings without executing tools.",
    )
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen ScheduleProof protocol")
    describe.add_argument("--json", action="store_true", dest="as_json")
    demo = commands.add_parser("demo", help="analyze all synthetic reference profiles")
    demo.add_argument("--json", action="store_true", dest="as_json")
    demo.add_argument("--out-dir", help="write each recomputable report to this directory")
    init = commands.add_parser("init", help="write a data-only starter scenario")
    init.add_argument("--profile", choices=tuple(BUILT_IN_PROFILES), default="hardened-payment")
    init.add_argument("--out", required=True)
    init.add_argument("--force", action="store_true")
    run = commands.add_parser("run", help="explore one ScheduleProof scenario")
    run.add_argument("path")
    run.add_argument("--json-out")
    run.add_argument("--sarif-out")
    run.add_argument("--fail-on-unsafe", action="store_true")
    run.add_argument(
        "--require-complete",
        action="store_true",
        help="also fail when the exploration ceiling truncates the schedule space",
    )
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
            print("ScheduleProof v1 — bounded agent authorization interleaving assurance")
            print(f"Protocol sha256: {_digest(payload)}")
            print("Invariants:")
            for key, value in payload["invariants"].items():
                print(f"  - {key}: {value}")
            print(payload["claim_boundary"])
        return 0
    if args.command == "init":
        destination = Path(args.out)
        if destination.exists() and not args.force:
            print(
                f"[schedule] kept existing {destination} (use --force to replace)", file=sys.stderr
            )
            return 2
        try:
            _write_json(destination, built_in_scenario(args.profile))
        except OSError as exc:
            print(f"[schedule] init failed: {exc}", file=sys.stderr)
            return 2
        print(f"[schedule] wrote {destination}")
        return 0
    if args.command == "verify":
        try:
            payload = _read_json(Path(args.path))
            errors = verify_schedule_report(payload)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors = (str(exc),)
        if errors:
            print("[schedule] verification failed: " + "; ".join(errors), file=sys.stderr)
            return 1
        print(f"[schedule] verified {args.path}")
        return 0
    if args.command == "demo":
        reports = [analyze_scenario(built_in_scenario(name)) for name in BUILT_IN_PROFILES]
        if args.out_dir:
            directory = Path(args.out_dir)
            try:
                for report in reports:
                    _write_json(
                        directory / f"{report['scenario']['scenario_id']}.report.json", report
                    )
            except OSError as exc:
                print(f"[schedule] demo failed: {exc}", file=sys.stderr)
                return 2
        if args.as_json:
            print(json.dumps(reports, indent=2, sort_keys=True))
        else:
            for report in reports:
                summary = report["summary"]
                print(
                    f"{report['scenario']['scenario_id']}: {summary['status']} · "
                    f"{summary['unsafe_schedules']}/{summary['schedules_explored']} unsafe "
                    f"of {summary['reachable_schedule_count']} reachable schedules"
                )
            print(
                "Unsafe-schedule fractions are explored schedule-space ratios, not probabilities."
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
            print(f"[schedule] wrote {args.json_out}")
        if args.sarif_out:
            _write_json(Path(args.sarif_out), schedule_report_to_sarif(report))
            print(f"[schedule] wrote {args.sarif_out}")
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[schedule] run failed: {exc}", file=sys.stderr)
        return 2
    summary = report["summary"]
    print(
        f"[schedule] {summary['status']}: {summary['unsafe_schedules']}/"
        f"{summary['schedules_explored']} explored schedules unsafe; "
        f"complete={str(summary['complete_exploration']).lower()}"
    )
    gate_failed = (args.fail_on_unsafe and summary["status"] == "unsafe") or (
        args.require_complete and not summary["complete_exploration"]
    )
    return 1 if gate_failed else 0


def _read_json(path: Path) -> dict:
    if path.stat().st_size > MAX_SCENARIO_BYTES:
        raise ValueError("ScheduleProof JSON input exceeds the 1 MiB boundary")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _digest(payload: dict) -> str:
    from dspy_security_bench.mission.loader import canonical_sha256

    return canonical_sha256(payload)
