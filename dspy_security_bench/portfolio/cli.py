"""ResilienceGraph command-line interface."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

from dspy_security_bench.portfolio.proof import (
    MAX_CAMPAIGN_BYTES,
    analyze_campaign,
    built_in_campaign,
    frontier_csv_rows,
    protocol_payload,
    protocol_sha256,
    verify_report,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench portfolio",
        description=(
            "Enumerate the exact non-dominated frontier of evidence-backed cyber-defense "
            "actions under declared resources, dependencies, floors, and stress scenarios."
        ),
    )
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen ResilienceGraph protocol")
    describe.add_argument("--json", action="store_true", dest="as_json")
    init = commands.add_parser("init", help="write the fictional cross-sector campaign")
    init.add_argument("--out", required=True)
    init.add_argument("--force", action="store_true")
    run = commands.add_parser("run", help="compute an exact feasible portfolio frontier")
    run.add_argument("campaign")
    run.add_argument("--json-out")
    run.add_argument("--csv-out")
    run.add_argument("--require-fully-robust", action="store_true")
    run.add_argument("--fail-on-exclusions", action="store_true")
    verify = commands.add_parser("verify", help="recompute a portfolio report offline")
    verify.add_argument("report")
    demo = commands.add_parser("demo", help="run the fictional cross-sector campaign")
    demo.add_argument("--out-dir")
    demo.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "describe":
            if args.as_json:
                print(json.dumps(protocol_payload(), indent=2, sort_keys=True))
            else:
                print("ResilienceGraph v1 — exact verified-defense portfolio planning")
                print(f"Protocol sha256: {protocol_sha256()}")
                print(
                    "All eligible subsets are enumerated; the output is a frontier, not a ranking."
                )
                print(protocol_payload()["claim_boundary"])
            return 0
        if args.command == "init":
            _write_once(Path(args.out), built_in_campaign(), args.force)
            print(f"[portfolio] created {args.out}")
            return 0
        if args.command == "run":
            report = analyze_campaign(_read_json(Path(args.campaign)))
            return _emit_report(report, args)
        if args.command == "verify":
            errors = verify_report(_read_json(Path(args.report)))
            if errors:
                print("[portfolio] verification failed: " + "; ".join(errors), file=sys.stderr)
                return 1
            print(f"[portfolio] verified {args.report}")
            return 0
        if args.command == "demo":
            campaign = built_in_campaign()
            report = analyze_campaign(campaign)
            if args.out_dir:
                out_dir = Path(args.out_dir)
                _write_json(out_dir / "campaign.json", campaign)
                _write_json(out_dir / "report.json", report)
                _write_csv(out_dir / "frontier.csv", report)
                print(f"[portfolio] wrote campaign, report, and frontier to {out_dir}")
            if args.as_json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                _print_summary(report)
            return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[portfolio] {args.command} failed: {exc}", file=sys.stderr)
        return 2
    return 0


def _emit_report(report: dict[str, Any], args: argparse.Namespace) -> int:
    if args.json_out:
        _write_json(Path(args.json_out), report)
        print(f"[portfolio] wrote {args.json_out}")
    if args.csv_out:
        _write_csv(Path(args.csv_out), report)
        print(f"[portfolio] wrote {args.csv_out}")
    _print_summary(report)
    summary = report["summary"]
    if args.require_fully_robust and not summary["fully_robust_portfolio_exists"]:
        return 1
    if args.fail_on_exclusions and summary["excluded_candidate_count"]:
        return 1
    return 0


def _print_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]
    enumeration = report["enumeration"]
    print(
        f"[portfolio] {summary['outcome']}: {enumeration['feasible_portfolio_count']} feasible / "
        f"{enumeration['total_subsets']} exact subsets; {enumeration['frontier_portfolio_count']} "
        f"non-dominated; fully_robust={summary['fully_robust_portfolio_exists']}"
    )
    if report["reference_selection"]:
        reference = report["reference_selection"]
        print(
            "[portfolio] deterministic reference (not a recommendation): "
            + ", ".join(reference["selected_action_ids"])
        )
    for item in report["candidate_eligibility"]:
        if not item["eligible"]:
            print(f"[portfolio] excluded {item['action_id']}: {'; '.join(item['reasons'])}")


def _read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_CAMPAIGN_BYTES:
        raise ValueError(f"input exceeds {MAX_CAMPAIGN_BYTES} bytes")
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write_once(path: Path, payload: dict[str, Any], force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} exists (use --force)")
    _write_json(path, payload)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _write_csv(path: Path, report: dict[str, Any]) -> None:
    rows = frontier_csv_rows(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0]) if rows else ["portfolio_id"]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
