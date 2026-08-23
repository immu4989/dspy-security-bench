"""TraceProof command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench trace",
        description="Convert local agent telemetry into privacy-bounded, reviewable evidence.",
    )
    commands = parser.add_subparsers(dest="command")
    policy = commands.add_parser("init-policy", help="write a deny-by-default redaction policy")
    policy.add_argument("--out", default="traceproof-redaction.yaml")
    policy.add_argument("--force", action="store_true")
    ingest = commands.add_parser("import", help="sanitize an OTLP JSON export offline")
    ingest.add_argument("source")
    ingest.add_argument("--policy")
    ingest.add_argument("--out", required=True)
    analyze = commands.add_parser("analyze", help="run deterministic authorization/effect rules")
    analyze.add_argument("evidence")
    analyze.add_argument("--out", required=True)
    analyze.add_argument("--sarif-out")
    analyze.add_argument("--oscal-out")
    synthesize = commands.add_parser(
        "synthesize", help="distill sanitized evidence into a replay twin"
    )
    synthesize.add_argument("evidence")
    synthesize.add_argument("--report")
    synthesize.add_argument("--out", required=True)
    export = commands.add_parser("export", help="export an analysis report as SARIF or OSCAL")
    export.add_argument("report")
    export.add_argument("--format", choices=("sarif", "oscal"), required=True)
    export.add_argument("--out", required=True)
    verify = commands.add_parser(
        "verify", help="verify evidence, a report, or a replay twin offline"
    )
    verify.add_argument("path")
    demo = commands.add_parser("demo", help="generate and analyze a synthetic unsafe trace")
    demo.add_argument("--out-dir")
    demo.add_argument("--json", action="store_true", dest="as_json")
    runtime = commands.add_parser(
        "runtime", help="instrument any supported agent without recording content"
    )
    runtime_commands = runtime.add_subparsers(dest="runtime_command")
    runtime_commands.add_parser("list", help="list supported runtime integration presets")
    runtime_doctor = runtime_commands.add_parser(
        "doctor", help="inspect runtime readiness without importing the agent"
    )
    runtime_doctor.add_argument("--root", default=".")
    runtime_doctor.add_argument("--framework")
    runtime_doctor.add_argument("--json", action="store_true", dest="as_json")
    runtime_scaffold = runtime_commands.add_parser(
        "scaffold", help="write a content-free TraceRecordingAgent target"
    )
    runtime_scaffold.add_argument("--agent", required=True, help="module:callable agent factory")
    runtime_scaffold.add_argument("--out", default="traceproof_target.py")
    runtime_scaffold.add_argument("--trace-out", default="artifacts/traceproof-otlp.json")
    runtime_scaffold.add_argument("--force", action="store_true")
    mcp = commands.add_parser(
        "mcp", help="probe sanitized evidence against the stable MCP authorization spec"
    )
    mcp_commands = mcp.add_subparsers(dest="mcp_command")
    mcp_analyze = mcp_commands.add_parser("analyze", help="build an MCP authorization probe")
    mcp_analyze.add_argument("evidence")
    mcp_analyze.add_argument("--out", required=True)
    mcp_verify = mcp_commands.add_parser("verify", help="recompute an MCP authorization probe")
    mcp_verify.add_argument("report")
    mcp_verify.add_argument("--evidence", required=True)
    challenge = commands.add_parser(
        "challenge", help="run the frozen synthetic sanitizer escape corpus"
    )
    challenge.add_argument("--out")
    challenge.add_argument("--json", action="store_true", dest="as_json")
    bundle = commands.add_parser(
        "bundle", help="create privacy-bounded community TraceProof evidence"
    )
    bundle.add_argument("evidence")
    bundle.add_argument("report")
    bundle.add_argument("--mcp-report")
    bundle.add_argument("--submitter", required=True)
    bundle.add_argument("--runtime", required=True)
    bundle.add_argument("--source-repository", required=True)
    bundle.add_argument("--notes", default="")
    bundle.add_argument("--out", required=True)
    submission = commands.add_parser(
        "verify-submission", help="verify a community TraceProof bundle offline"
    )
    submission.add_argument("path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    from dspy_security_bench.trace.proof import (
        analyze_trace_evidence,
        build_trace_evidence,
        default_redaction_policy,
        demo_otlp_payload,
        export_oscal,
        export_sarif,
        synthesize_trace_twin,
        verify_trace_artifact,
    )

    try:
        if args.command == "init-policy":
            path = Path(args.out)
            if path.exists() and not args.force:
                print(f"[trace] kept existing {path} (use --force to replace)", file=sys.stderr)
                return 1
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(yaml.safe_dump(default_redaction_policy(), sort_keys=False))
            print(f"[trace] created {path}")
            return 0
        if args.command == "import":
            evidence = build_trace_evidence(args.source, policy_path=args.policy)
            _write(args.out, evidence)
            print(
                f"[trace] sanitized {evidence['span_count']} spans across {evidence['trace_count']} traces"
            )
            print(f"[trace] wrote {args.out} ({evidence['evidence_sha256']})")
            return 0
        if args.command == "analyze":
            evidence = _read(args.evidence)
            report = analyze_trace_evidence(evidence)
            _write(args.out, report)
            if args.sarif_out:
                _write(args.sarif_out, export_sarif(report))
            if args.oscal_out:
                _write(args.oscal_out, export_oscal(report))
            summary = report["summary"]
            print(
                f"[trace] {summary['finding_count']} findings; review_required={str(summary['review_required']).lower()}"
            )
            print(f"[trace] wrote {args.out}")
            return 1 if summary["critical"] or summary["high"] else 0
        if args.command == "synthesize":
            evidence = _read(args.evidence)
            report = _read(args.report) if args.report else None
            twin = synthesize_trace_twin(evidence, report)
            _write(args.out, twin)
            print(f"[trace] wrote privacy-bounded replay twin {args.out}")
            return 0
        if args.command == "export":
            report = _read(args.report)
            payload = export_sarif(report) if args.format == "sarif" else export_oscal(report)
            _write(args.out, payload)
            print(f"[trace] wrote {args.format.upper()} {args.out}")
            return 0
        if args.command == "verify":
            payload = _read(args.path)
            errors = verify_trace_artifact(payload)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[trace] verified {args.path}")
            return 0
        if args.command == "demo":
            evidence = build_trace_evidence(demo_otlp_payload())
            report = analyze_trace_evidence(evidence)
            twin = synthesize_trace_twin(evidence, report)
            if args.out_dir:
                root = Path(args.out_dir)
                root.mkdir(parents=True, exist_ok=True)
                _write(root / "trace-evidence.json", evidence)
                _write(root / "trace-report.json", report)
                _write(root / "trace-twin.json", twin)
                _write(root / "trace-results.sarif", export_sarif(report))
                _write(root / "assessment-results.json", export_oscal(report))
                print(f"[trace] wrote five demo artifacts to {root}")
            if args.as_json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                summary = report["summary"]
                print(
                    f"TraceProof synthetic demo: {summary['finding_count']} findings "
                    f"({summary['critical']} critical, {summary['high']} high)"
                )
                print("Synthetic fixture only; no product, deployment, or model was evaluated.")
            return 0
        if args.command == "runtime":
            return _runtime(args)
        if args.command == "mcp":
            return _mcp(args)
        if args.command == "challenge":
            from dspy_security_bench.trace.challenge import run_redaction_challenge

            report = run_redaction_challenge()
            if args.out:
                _write(args.out, report)
                print(f"[trace] wrote redaction challenge {args.out}")
            if args.as_json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print(
                    f"TraceProof redaction challenge: {report['passed_count']}/{report['case_count']} "
                    f"passed; {report['escaped_count']} escaped"
                )
                print("Synthetic corpus only; passing does not prove arbitrary telemetry is safe.")
            return 0 if report["status"] == "pass" else 1
        if args.command == "bundle":
            from dspy_security_bench.trace.evidence import build_trace_submission_bundle

            bundle = build_trace_submission_bundle(
                _read(args.evidence),
                _read(args.report),
                submitter=args.submitter,
                runtime=args.runtime,
                source_repository_url=args.source_repository,
                notes=args.notes,
                mcp_report=_read(args.mcp_report) if args.mcp_report else None,
            )
            _write(args.out, bundle)
            print(f"[trace] wrote self-attested community bundle {args.out}")
            return 0
        if args.command == "verify-submission":
            from dspy_security_bench.trace.evidence import verify_trace_submission_bundle

            verification = verify_trace_submission_bundle(_read(args.path))
            for warning in verification.warnings:
                print(f"[trace] note: {warning}")
            if verification.errors:
                raise ValueError("; ".join(verification.errors))
            if not verification.community_eligible:
                print("[trace] valid but not eligible for the community registry", file=sys.stderr)
                return 1
            print(f"[trace] verified community-eligible bundle {args.path}")
            return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[trace] failed: {exc}", file=sys.stderr)
        return 2
    return 2


def _read(path: str | Path) -> dict:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write(path: str | Path, payload: dict) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _runtime(args) -> int:
    from dspy_security_bench.trace.runtime import (
        runtime_catalog,
        runtime_doctor,
        runtime_scaffold,
    )

    if args.runtime_command is None:
        print("Usage: dspy-security-bench trace runtime <list|doctor|scaffold> [args...]")
        return 0
    if args.runtime_command == "list":
        for item in runtime_catalog():
            print(f"{item['key']:16} {item['label']} — {item['hook']}")
        return 0
    if args.runtime_command == "doctor":
        report = runtime_doctor(args.root, framework=args.framework)
        if args.as_json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            for check in report["checks"]:
                print(f"[{check['status'].upper():4}] {check['name']}: {check['detail']}")
            print(report["non_execution_claim"])
        return 0 if report["ready"] else 1
    if args.runtime_command == "scaffold":
        path = Path(args.out)
        if path.exists() and not args.force:
            print(f"[trace] kept existing {path} (use --force to replace)", file=sys.stderr)
            return 1
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(runtime_scaffold(args.agent, output_path=args.trace_out), encoding="utf-8")
        print(f"[trace] created content-free runtime target {path}")
        print(f"Next: review security_context, then import build_traced_agent from {path.stem}")
        return 0
    return 2


def _mcp(args) -> int:
    from dspy_security_bench.trace.mcp import (
        analyze_mcp_authorization,
        verify_mcp_authorization_report,
    )

    if args.mcp_command is None:
        print("Usage: dspy-security-bench trace mcp <analyze|verify> [args...]")
        return 0
    if args.mcp_command == "analyze":
        report = analyze_mcp_authorization(_read(args.evidence))
        _write(args.out, report)
        summary = report["summary"]
        print(
            f"[trace] MCP {report['specification_revision']}: "
            f"{summary['required_pass_count']}/{summary['required_check_count']} required probes pass"
        )
        print(f"[trace] wrote {args.out}")
        return 1 if summary["review_required"] else 0
    if args.mcp_command == "verify":
        errors = verify_mcp_authorization_report(_read(args.report), _read(args.evidence))
        if errors:
            raise ValueError("; ".join(errors))
        print(f"[trace] verified MCP authorization probe {args.report}")
        return 0
    return 2
