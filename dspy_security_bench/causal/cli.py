"""CausalProof command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dspy_security_bench.causal.proof import (
    MAX_MANIFEST_BYTES,
    analyze_causality,
    build_demo_inputs,
    protocol_payload,
    read_trace_file,
    verify_causal_report,
)
from dspy_security_bench.schedule.proof import analyze_scenario


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench causal",
        description="Convert structural OTLP causality into a provenance-separated ScheduleProof draft.",
    )
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen CausalProof protocol")
    describe.add_argument("--json", action="store_true", dest="as_json")
    demo = commands.add_parser("demo", help="run the fictional content-free reference case")
    demo.add_argument("--out-dir")
    init = commands.add_parser("init", help="write fictional starter OTLP and binding files")
    init.add_argument("--trace-out", required=True)
    init.add_argument("--manifest-out", required=True)
    init.add_argument("--force", action="store_true")
    run = commands.add_parser("run", help="convert OTLP structural evidence into a proof graph")
    run.add_argument("trace")
    run.add_argument("manifest")
    run.add_argument("--report-out", required=True)
    run.add_argument("--scenario-out")
    run.add_argument("--schedule-report-out")
    run.add_argument("--fail-on-review", action="store_true")
    run.add_argument("--fail-on-unsafe", action="store_true")
    run.add_argument("--require-complete", action="store_true")
    verify = commands.add_parser("verify", help="recompute a report from trace and manifest")
    verify.add_argument("report")
    verify.add_argument("trace")
    verify.add_argument("manifest")
    bundle = commands.add_parser("bundle", help="build a content-free community submission")
    bundle.add_argument("trace")
    bundle.add_argument("manifest")
    bundle.add_argument("--submitter", required=True)
    bundle.add_argument("--runtime", required=True)
    bundle.add_argument("--source-repository", required=True)
    bundle.add_argument("--known-gap", action="append", default=[])
    bundle.add_argument("--out", required=True)
    verify_submission = commands.add_parser(
        "verify-submission", help="recompute a public CausalProof bundle"
    )
    verify_submission.add_argument("path")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "describe":
        payload = protocol_payload()
        if args.as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("CausalProof v1 — structural runtime causality to ScheduleProof")
            for provenance, meaning in payload["provenance_classes"].items():
                print(f"  - {provenance}: {meaning}")
            print(payload["claim_boundary"])
        return 0
    if args.command in {"demo", "init"}:
        trace, manifest = build_demo_inputs()
        if args.command == "init":
            destinations = (Path(args.trace_out), Path(args.manifest_out))
            if not args.force and any(path.exists() for path in destinations):
                print("[causal] kept existing starter file (use --force to replace)", file=sys.stderr)
                return 2
            _write(destinations[0], trace)
            _write(destinations[1], manifest)
            print(f"[causal] wrote {destinations[0]} and {destinations[1]}")
            return 0
        report = analyze_causality(trace, manifest)
        schedule_report = analyze_scenario(report["schedule_scenario"])
        if args.out_dir:
            directory = Path(args.out_dir)
            _write(directory / "causalproof.report.json", report)
            _write(directory / "scheduleproof.scenario.json", report["schedule_scenario"])
            _write(directory / "scheduleproof.report.json", schedule_report)
        _print_summary(report, schedule_report)
        return 0
    try:
        if args.command == "verify-submission":
            from dspy_security_bench.causal.registry import verify_causal_submission_bundle

            result = verify_causal_submission_bundle(
                _read(Path(args.path), MAX_MANIFEST_BYTES * 8)
            )
            for warning in result.warnings:
                print(f"[causal] note: {warning}", file=sys.stderr)
            if result.errors:
                print("[causal] submission invalid: " + "; ".join(result.errors), file=sys.stderr)
                return 1
            print(f"[causal] verified community submission {args.path}")
            return 0
        if args.command == "bundle":
            from dspy_security_bench.causal.registry import build_causal_submission_bundle

            trace, _ = read_trace_file(Path(args.trace))
            manifest = _read(Path(args.manifest), MAX_MANIFEST_BYTES)
            payload = build_causal_submission_bundle(
                trace,
                manifest,
                submitter=args.submitter,
                runtime=args.runtime,
                source_repository=args.source_repository,
                known_gaps=args.known_gap or None,
            )
            _write(Path(args.out), payload)
            print(f"[causal] wrote content-free community submission {args.out}")
            return 0
        if args.command == "verify":
            trace, source_digest = read_trace_file(Path(args.trace))
            manifest = _read(Path(args.manifest), MAX_MANIFEST_BYTES)
            report = _read(Path(args.report), MAX_MANIFEST_BYTES * 4)
            errors = verify_causal_report(
                report, trace, manifest, source_sha256=source_digest
            )
            if errors:
                print("[causal] verification failed: " + "; ".join(errors), file=sys.stderr)
                return 1
            print(f"[causal] verified {args.report}")
            return 0
        trace, source_digest = read_trace_file(Path(args.trace))
        manifest = _read(Path(args.manifest), MAX_MANIFEST_BYTES)
        report = analyze_causality(trace, manifest, source_sha256=source_digest)
        _write(Path(args.report_out), report)
        if args.scenario_out and report["schedule_scenario"] is not None:
            _write(Path(args.scenario_out), report["schedule_scenario"])
        schedule_report = None
        if report["schedule_scenario"] is not None and (
            args.schedule_report_out or args.fail_on_unsafe or args.require_complete
        ):
            schedule_report = analyze_scenario(report["schedule_scenario"])
            if args.schedule_report_out:
                _write(Path(args.schedule_report_out), schedule_report)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"[causal] failed: {exc}", file=sys.stderr)
        return 2
    _print_summary(report, schedule_report)
    failed = args.fail_on_review and report["summary"]["status"] != "ready"
    if schedule_report:
        failed = failed or (args.fail_on_unsafe and schedule_report["summary"]["status"] == "unsafe")
        failed = failed or (
            args.require_complete and not schedule_report["summary"]["complete_exploration"]
        )
    return 1 if failed else 0


def _read(path: Path, limit: int) -> dict:
    if path.stat().st_size > limit:
        raise ValueError(f"JSON input {path} exceeds its byte boundary")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON input root must be an object")
    return payload


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _print_summary(report: dict, schedule_report: dict | None) -> None:
    summary = report["summary"]
    message = (
        f"[causal] {summary['status']}: {summary['matched_events']}/{summary['bound_events']} "
        f"events matched; {summary['trusted_edges']} trusted edges; "
        f"{summary['observed_links']} undirected links; "
        f"{summary['timing_candidates']} non-proving timing candidates"
    )
    if schedule_report:
        schedule = schedule_report["summary"]
        message += (
            f"; ScheduleProof={schedule['status']} "
            f"({schedule['unsafe_schedules']}/{schedule['schedules_explored']} unsafe)"
        )
    print(message)
