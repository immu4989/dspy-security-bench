"""AssuranceGraph command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from dspy_security_bench.assurance.case import (
    MAX_CASE_BYTES,
    MAX_EVIDENCE_BYTES,
    analyze_case,
    built_in_case,
    protocol_payload,
    protocol_sha256,
    seal_case,
    verify_report,
)
from dspy_security_bench.assurance.exchange import (
    exchange_summary,
    load_exchange,
    seal_exchange,
    validate_exchange,
)
from dspy_security_bench.assurance.exports import export_oscal, export_sarif, render_html
from dspy_security_bench.assurance.federal import export_review_pack, verify_review_pack
from dspy_security_bench.assurance.profiles import built_in_profile, profile_ids
from dspy_security_bench.assurance.sectors import sector_case, sector_ids, sector_profile
from dspy_security_bench.mission.loader import canonical_sha256


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench assure",
        description=(
            "Compile verified local evidence into an executable, non-certifying agent assurance case."
        ),
    )
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen AssuranceGraph protocol")
    describe.add_argument("--json", action="store_true", dest="as_json")
    profiles = commands.add_parser("profiles", help="list or inspect built-in adoption profiles")
    profiles.add_argument("profile_id", nargs="?", choices=profile_ids())
    profiles.add_argument("--json", action="store_true", dest="as_json")
    sectors = commands.add_parser("sectors", help="list or inspect fictional sector starters")
    sectors.add_argument("sector_id", nargs="?", choices=sector_ids())
    sectors.add_argument("--json", action="store_true", dest="as_json")
    digest = commands.add_parser(
        "digest", help="natively verify an evidence report and print its canonical digest"
    )
    digest.add_argument("evidence")
    digest.add_argument("--json", action="store_true", dest="as_json")
    init = commands.add_parser("init", help="write an editable assurance case")
    init_source = init.add_mutually_exclusive_group(required=True)
    init_source.add_argument("--profile", choices=profile_ids())
    init_source.add_argument("--sector", choices=sector_ids())
    init.add_argument("--case-id", default=None)
    init.add_argument("--evaluation-time", type=int, default=None)
    init.add_argument("--out", required=True)
    init.add_argument("--force", action="store_true")
    evaluate = commands.add_parser("evaluate", help="verify evidence and evaluate every claim")
    evaluate.add_argument("case")
    evaluate.add_argument("--evidence-root", required=True)
    evaluate.add_argument("--out", required=True)
    evaluate.add_argument("--sarif-out")
    evaluate.add_argument("--oscal-out")
    evaluate.add_argument("--html-out")
    evaluate.add_argument("--fail-on-review", action="store_true")
    verify = commands.add_parser("verify", help="recompute an AssuranceGraph report offline")
    verify.add_argument("report")
    verify.add_argument("--evidence-root", required=True)
    federal_pack = commands.add_parser(
        "federal-pack", help="export integrity-verifiable, non-certifying federal review inputs"
    )
    federal_pack.add_argument("report")
    federal_pack.add_argument("--evidence-root", required=True)
    federal_pack.add_argument("--out-dir", required=True)
    federal_pack.add_argument("--force", action="store_true")
    federal_verify = commands.add_parser(
        "federal-verify", help="recompute an AssuranceGraph federal review pack offline"
    )
    federal_verify.add_argument("pack")
    federal_verify.add_argument("--evidence-root", required=True)
    exchange_verify = commands.add_parser(
        "exchange-verify", help="validate the non-ranking public assurance metadata exchange"
    )
    exchange_verify.add_argument("index", nargs="?", default="submissions/assurance/index.json")
    exchange_verify.add_argument("--json", action="store_true", dest="as_json")
    exchange_seal = commands.add_parser(
        "exchange-seal", help="validate and content-address an edited assurance exchange"
    )
    exchange_seal.add_argument("index")
    exchange_seal.add_argument("--out", required=True)
    exchange_seal.add_argument("--force", action="store_true")
    demo = commands.add_parser("demo", help="build and evaluate a complete fictional case")
    demo.add_argument("--out-dir", required=True)
    demo.add_argument("--profile", default="critical-infrastructure", choices=profile_ids())
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
                print("AssuranceGraph v1 — executable claim-evidence cases")
                print(f"Protocol sha256: {protocol_sha256()}")
                print(protocol_payload()["claim_boundary"])
            return 0
        if args.command == "profiles":
            if args.profile_id:
                profile = built_in_profile(args.profile_id)
                if args.as_json:
                    print(json.dumps(profile, indent=2, sort_keys=True))
                else:
                    _print_profile(profile)
            else:
                for profile_id in profile_ids():
                    profile = built_in_profile(profile_id)
                    print(f"{profile_id:24} {len(profile['claims'])} claims  {profile['title']}")
            return 0
        if args.command == "sectors":
            if args.sector_id:
                sector = sector_profile(args.sector_id)
                if args.as_json:
                    print(json.dumps(sector, indent=2, sort_keys=True))
                else:
                    print(f"{sector['title']} ({sector['sector_id']})")
                    print(f"Profile: {sector['profile_id']}")
                    print(f"Mission: {sector['mission']}")
                    print(f"Boundary: {sector['boundary']}")
                    print(sector["claim_boundary"])
            else:
                rows = [sector_profile(sector_id) for sector_id in sector_ids()]
                if args.as_json:
                    print(json.dumps(rows, indent=2, sort_keys=True))
                else:
                    for sector in rows:
                        print(
                            f"{sector['sector_id']:28} {sector['profile_id']:24} {sector['title']}"
                        )
            return 0
        if args.command == "digest":
            from dspy_security_bench.continuous.proof import build_evidence_snapshot

            payload = _read_json(Path(args.evidence), MAX_EVIDENCE_BYTES)
            snapshot = build_evidence_snapshot(payload, label=Path(args.evidence).name)
            result = {
                "evidence_kind": snapshot["evidence_kind"],
                "expected_sha256": snapshot["evidence_sha256"],
            }
            if args.as_json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(result["expected_sha256"])
            return 0
        if args.command == "init":
            evaluation_time = (
                int(time.time()) if args.evaluation_time is None else args.evaluation_time
            )
            case = (
                sector_case(args.sector, case_id=args.case_id, evaluation_time=evaluation_time)
                if args.sector
                else built_in_case(
                    args.profile,
                    case_id=args.case_id or "example-agent-assurance",
                    evaluation_time=evaluation_time,
                )
            )
            _write_once(Path(args.out), _json(case), args.force)
            print(f"[assure] created {args.out}")
            print("[assure] replace the fictional boundary, owners, times, and evidence paths")
            print("[assure] pin every artifact with: dspy-security-bench assure digest FILE")
            return 0
        if args.command == "evaluate":
            case = _read_json(Path(args.case), MAX_CASE_BYTES)
            report = analyze_case(case, args.evidence_root)
            _write(Path(args.out), _json(report))
            if args.sarif_out:
                _write(Path(args.sarif_out), _json(export_sarif(report)))
            if args.oscal_out:
                _write(Path(args.oscal_out), _json(export_oscal(report)))
            if args.html_out:
                _write(Path(args.html_out), render_html(report))
            _print_report(report)
            if args.fail_on_review and report["summary"]["status"] != "profile_evidence_supported":
                return 1
            return 0
        if args.command == "verify":
            report = _read_json(Path(args.report), 2 * MAX_CASE_BYTES)
            errors = verify_report(report, args.evidence_root)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[assure] verified {args.report}")
            return 0
        if args.command == "federal-pack":
            report = _read_json(Path(args.report), 2 * MAX_CASE_BYTES)
            manifest = export_review_pack(
                report,
                args.evidence_root,
                args.out_dir,
                force=args.force,
            )
            print(f"[assure] federal review inputs: {manifest['pack_sha256']}")
            print("[assure] control determinations=0 risk acceptances=0 ATOs=0")
            return 0
        if args.command == "federal-verify":
            errors = verify_review_pack(args.pack, args.evidence_root)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[assure] verified federal review pack: {args.pack}")
            return 0
        if args.command == "exchange-verify":
            exchange = load_exchange(args.index)
            summary = exchange_summary(exchange)
            if args.as_json:
                print(json.dumps(summary, indent=2, sort_keys=True))
            else:
                print(
                    f"[assure] exchange valid: {summary['entryCount']} entries; "
                    f"{summary['independentReproductionCount']} independent reproductions; "
                    "ranking=false endorsements=0"
                )
            return 0
        if args.command == "exchange-seal":
            exchange = _read_json(Path(args.index), 10 * MAX_CASE_BYTES)
            sealed = seal_exchange(exchange)
            errors = validate_exchange(sealed)
            if errors:
                raise ValueError("; ".join(errors))
            _write_once(Path(args.out), _json(sealed), args.force)
            print(f"[assure] sealed exchange: {sealed['registry_sha256']}")
            return 0
        if args.command == "demo":
            _write_demo(Path(args.out_dir), args.profile, args.force)
            return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[assure] {args.command} failed: {exc}", file=sys.stderr)
        return 2
    return 0


def _write_demo(out_dir: Path, profile_id: str, force: bool) -> None:
    if out_dir.exists() and any(out_dir.iterdir()) and not force:
        raise ValueError(f"output directory is not empty: {out_dir} (use --force)")
    evidence_dir = out_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence = _demo_evidence()
    case = built_in_case(profile_id)
    for item in case["evidence"]:
        payload = evidence[item["evidence_kind"]]
        item["owner"] = "fictional-reference-evidence-owner"
        item["expected_sha256"] = canonical_sha256(payload)
        _write(evidence_dir / f"{item['evidence_kind']}.json", _json(payload))
    case["decision_owner"] = "fictional-reference-decision-owner"
    case["title"] = "Fictional critical-service agent assurance case"
    case["description"] = (
        "A complete synthetic case demonstrating verified evidence composition. It contains no "
        "production claim, operational data, live target, or deployment approval."
    )
    case = seal_case(case)
    _write(out_dir / "assurance-case.json", _json(case))
    report = analyze_case(case, out_dir)
    _write(out_dir / "assurance-report.json", _json(report))
    _write(out_dir / "assurance.sarif", _json(export_sarif(report)))
    _write(out_dir / "assessment-results.json", _json(export_oscal(report)))
    _write(out_dir / "index.html", render_html(report))
    print(
        f"[assure] {report['summary']['status']}: wrote case, {len(case['evidence'])} verified "
        f"artifacts, JSON report, SARIF, OSCAL, and HTML to {out_dir}"
    )


def _demo_evidence() -> dict[str, dict[str, Any]]:
    from dspy_security_bench.authority.adapter import build_bounded_authority_adapter
    from dspy_security_bench.authority.benchmark import run_authority_twin
    from dspy_security_bench.collective.v2 import (
        analyze_scenario_v2,
        built_in_scenario_v2,
    )
    from dspy_security_bench.containment.proof import (
        analyze_scenario as analyze_containment,
    )
    from dspy_security_bench.containment.proof import (
        built_in_scenario as built_in_containment,
    )
    from dspy_security_bench.defend.protocol import (
        analyze_remediation,
        built_in_mission,
        built_in_proposal,
    )
    from dspy_security_bench.evalguard.proof import (
        analyze_scenario as analyze_eval_integrity,
    )
    from dspy_security_bench.evalguard.proof import (
        built_in_scenario as built_in_eval_integrity,
    )
    from dspy_security_bench.portfolio.proof import analyze_campaign, built_in_campaign
    from dspy_security_bench.schedule.proof import analyze_scenario, built_in_scenario
    from dspy_security_bench.supplychain.proof import analyze_change, built_in_inventory
    from dspy_security_bench.trace.proof import analyze_trace_evidence, build_trace_evidence

    def authority_factory():
        return build_bounded_authority_adapter()

    authority = run_authority_twin(authority_factory(), adapter_factory=authority_factory).to_dict()
    trace = analyze_trace_evidence(build_trace_evidence(_clean_demo_otlp()))
    collective = analyze_scenario_v2(built_in_scenario_v2("hardened-complete"))
    schedule = analyze_scenario(built_in_scenario("hardened-payment"))
    mission = built_in_mission("water-utility")
    defense = analyze_remediation(mission, built_in_proposal(mission))
    portfolio = analyze_campaign(built_in_campaign())
    containment = analyze_containment(built_in_containment("hardened-reference"))
    evaluation_integrity = analyze_eval_integrity(built_in_eval_integrity("integrity-reference"))
    inventory = built_in_inventory("baseline")
    dependency_impact = analyze_change(
        inventory,
        built_in_inventory("equivalent"),
        change_reason="no material content change",
    )
    return {
        "authority": authority,
        "trace": trace,
        "collective-v2": collective,
        "schedule": schedule,
        "verified-defense": defense,
        "defense-portfolio": portfolio,
        "containment": containment,
        "evaluation-integrity": evaluation_integrity,
        "dependency-impact": dependency_impact,
    }


def _clean_demo_otlp() -> dict[str, Any]:
    action = "a" * 64
    return {
        "spans": [
            {
                "traceId": "0123456789abcdef0123456789abcdef",
                "spanId": "0123456789abcdef",
                "name": "synthetic authorized tool effect",
                "startTimeUnixNano": "1000000000",
                "endTimeUnixNano": "1010000000",
                "status": {"code": 1},
                "attributes": {
                    "gen_ai.operation.name": "execute_tool",
                    "gen_ai.agent.name": "synthetic-bounded-agent",
                    "gen_ai.tool.name": "synthetic.effect",
                    "dsb.auth.required": True,
                    "dsb.auth.decision": "allow",
                    "dsb.auth.token_audience": "mcp://synthetic-resource",
                    "dsb.auth.resource": "mcp://synthetic-resource",
                    "dsb.auth.requested_scopes": ["synthetic:write"],
                    "dsb.auth.granted_scopes": ["synthetic:write"],
                    "dsb.auth.token_passthrough": False,
                    "dsb.approval.required": True,
                    "dsb.approval.completed": True,
                    "dsb.approval.bound_action_sha256": action,
                    "dsb.effect.action_sha256": action,
                    "dsb.auth.agent_id": "synthetic-bounded-agent",
                    "dsb.delegation.agent_id": "synthetic-bounded-agent",
                    "dsb.auth.grant_revoked": False,
                    "dsb.auth.step_up_required": False,
                    "dsb.auth.step_up_completed": False,
                    "dsb.auth.retry_count": 0,
                    "dsb.effect.external": True,
                    "dsb.effect.receipt_id": "synthetic-receipt-1",
                },
            }
        ]
    }


def _print_profile(profile: dict[str, Any]) -> None:
    print(f"{profile['title']} ({profile['profile_id']})")
    print(profile["purpose"])
    print(f"Default evidence age: {profile['default_max_age_seconds']} seconds")
    for claim in profile["claims"]:
        print(f"- {claim['claim_id']}: {claim['evidence_kind']} ({claim['criticality']})")
    print(profile["claim_boundary"])


def _print_report(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(
        f"[assure] {summary['status']}: {summary['claim_status_counts']['supported']}/"
        f"{summary['claim_count']} claims supported; automatic_actions=0"
    )
    for claim in report["claim_results"]:
        print(f"[assure] {claim['status']:18} {claim['claim_id']}")


def _read_json(path: Path, maximum: int) -> dict[str, Any]:
    if path.stat().st_size > maximum:
        raise ValueError(f"input exceeds {maximum} bytes")
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write_once(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} exists (use --force)")
    _write(path, content)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
