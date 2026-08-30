"""ContainmentProof command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dspy_security_bench.containment.proof import (
    BUILT_IN_PROFILES,
    MAX_SCENARIO_BYTES,
    analyze_scenario,
    built_in_scenario,
    protocol_payload,
    protocol_sha256,
    validate_scenario,
    verify_report,
)
from dspy_security_bench.containment.sarif import report_to_sarif


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench contain",
        description="Analyze harmless canary containment records without executing an agent.",
    )
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen protocol")
    describe.add_argument("--json", action="store_true", dest="as_json")
    init = commands.add_parser("init", help="write a data-only starter scenario")
    init.add_argument("--profile", choices=BUILT_IN_PROFILES, default="hardened-reference")
    init.add_argument("--out", required=True)
    init.add_argument("--force", action="store_true")
    run = commands.add_parser("run", help="analyze one canary observation record")
    run.add_argument("scenario")
    run.add_argument("--json-out", required=True)
    run.add_argument("--sarif-out")
    run.add_argument("--fail-on-review", action="store_true")
    verify = commands.add_parser("verify", help="recompute a report offline")
    verify.add_argument("report")
    demo = commands.add_parser("demo", help="write all fictional reference outcomes")
    demo.add_argument("--out-dir", required=True)
    demo.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "describe":
            if args.as_json:
                print(json.dumps(protocol_payload(), indent=2, sort_keys=True))
            else:
                print("ContainmentProof v1 — harmless canary-based agent control evidence")
                print(f"Protocol sha256: {protocol_sha256()}")
                print(protocol_payload()["claim_boundary"])
            return 0
        if args.command == "init":
            target = Path(args.out)
            if target.exists() and not args.force:
                raise FileExistsError(f"{target} exists (use --force)")
            _write_json(target, built_in_scenario(args.profile))
            print(f"[contain] wrote {target}")
            return 0
        if args.command == "run":
            scenario = _read_json(Path(args.scenario), MAX_SCENARIO_BYTES)
            scenario_errors = validate_scenario(scenario)
            if scenario_errors:
                raise ValueError("; ".join(scenario_errors))
            report = analyze_scenario(scenario)
            _write_json(Path(args.json_out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), report_to_sarif(report))
            print(f"[contain] {report['summary']['status']}: wrote {args.json_out}")
            return int(args.fail_on_review and report["summary"]["status"] != "contained")
        if args.command == "verify":
            report = _read_json(Path(args.report), 2 * MAX_SCENARIO_BYTES)
            errors = verify_report(report)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[contain] verified {args.report}")
            return 0
        if args.command == "demo":
            destination = Path(args.out_dir)
            if destination.exists() and any(destination.iterdir()) and not args.force:
                raise ValueError(f"output directory is not empty: {destination} (use --force)")
            for profile in BUILT_IN_PROFILES:
                scenario = built_in_scenario(profile)
                report = analyze_scenario(scenario)
                _write_json(destination / f"{profile}.scenario.json", scenario)
                _write_json(destination / f"{profile}.report.json", report)
                _write_json(destination / f"{profile}.sarif", report_to_sarif(report))
                print(f"[contain] {profile}: {report['summary']['status']}")
            return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[contain] {args.command} failed: {exc}", file=sys.stderr)
        return 2
    return 0


def _read_json(path: Path, maximum: int) -> dict[str, Any]:
    if path.stat().st_size > maximum:
        raise ValueError(f"input exceeds {maximum} bytes")
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
