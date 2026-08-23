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
