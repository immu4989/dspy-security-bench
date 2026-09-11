"""AgentBOM and ClaimImpact command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dspy_security_bench.supplychain.mlbom import (
    build_mlbom_import_report,
    verify_mlbom_import_report,
)
from dspy_security_bench.supplychain.proof import (
    MAX_INVENTORY_BYTES,
    analyze_change,
    built_in_inventory,
    import_cyclonedx,
    import_spdx,
    protocol_payload,
    protocol_sha256,
    report_to_sarif,
    validate_inventory,
    verify_report,
)
from dspy_security_bench.supplychain.slsa import (
    build_slsa_import_report,
    verify_slsa_import_report,
)
from dspy_security_bench.supplychain.spdxai import (
    build_spdx_ai_import_report,
    verify_spdx_ai_import_report,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench bom",
        description="Map local AI-agent dependencies to assurance reevaluation without network access.",
    )
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen AgentBOM protocol")
    describe.add_argument("--json", action="store_true", dest="as_json")
    init = commands.add_parser("init", help="write a fictional editable AgentBOM")
    init.add_argument(
        "--revision", choices=("baseline", "candidate", "equivalent"), default="baseline"
    )
    init.add_argument("--out", required=True)
    init.add_argument("--force", action="store_true")
    for command, label in (("import-cyclonedx", "CycloneDX"), ("import-spdx", "SPDX")):
        imported = commands.add_parser(
            command, help=f"convert local {label} JSON into an editable AgentBOM"
        )
        imported.add_argument("source")
        imported.add_argument("--inventory-id", required=True)
        imported.add_argument("--out", required=True)
        imported.add_argument("--force", action="store_true")
    import_slsa = commands.add_parser(
        "import-slsa",
        help="privacy-minimize SLSA Provenance v1 into an incomplete AgentBOM",
    )
    import_slsa.add_argument("source")
    import_slsa.add_argument("--inventory-id", required=True)
    import_slsa.add_argument("--out", required=True)
    import_slsa.add_argument("--report-out", required=True)
    import_slsa.add_argument("--force", action="store_true")
    verify_slsa = commands.add_parser(
        "verify-slsa-import",
        help="recompute a SLSA-to-AgentBOM mapping from the retained Statement",
    )
    verify_slsa.add_argument("report")
    verify_slsa.add_argument("source")
    import_mlbom = commands.add_parser(
        "import-mlbom",
        help="privacy-minimize CycloneDX 1.7 ML-BOM and map disclosure gaps",
    )
    import_mlbom.add_argument("source")
    import_mlbom.add_argument("--inventory-id", required=True)
    import_mlbom.add_argument("--out", required=True)
    import_mlbom.add_argument("--report-out", required=True)
    import_mlbom.add_argument("--force", action="store_true")
    verify_mlbom = commands.add_parser(
        "verify-mlbom-import",
        help="recompute an ML-BOM disclosure mapping from the retained source",
    )
    verify_mlbom.add_argument("report")
    verify_mlbom.add_argument("source")
    import_spdx_ai = commands.add_parser(
        "import-spdx-ai",
        help="privacy-minimize SPDX 3.0.1 AI/Dataset profile disclosure gaps",
    )
    import_spdx_ai.add_argument("source")
    import_spdx_ai.add_argument("--inventory-id", required=True)
    import_spdx_ai.add_argument("--out", required=True)
    import_spdx_ai.add_argument("--report-out", required=True)
    import_spdx_ai.add_argument("--force", action="store_true")
    verify_spdx_ai = commands.add_parser(
        "verify-spdx-ai-import",
        help="recompute an SPDX AI disclosure mapping from the retained source",
    )
    verify_spdx_ai.add_argument("report")
    verify_spdx_ai.add_argument("source")
    compare = commands.add_parser("compare", help="compute transitive claim impact")
    compare.add_argument("baseline")
    compare.add_argument("candidate")
    compare.add_argument("--reason", required=True)
    compare.add_argument("--json-out", required=True)
    compare.add_argument("--sarif-out")
    compare.add_argument("--fail-on-reevaluation", action="store_true")
    verify = commands.add_parser("verify", help="recompute a ClaimImpact report offline")
    verify.add_argument("report")
    demo = commands.add_parser("demo", help="write fictional unchanged and changed inventories")
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
                print("AgentBOM + ClaimImpact v1 — dependency-aware assurance invalidation")
                print(f"Protocol sha256: {protocol_sha256()}")
                print(protocol_payload()["claim_boundary"])
            return 0
        if args.command == "init":
            target = Path(args.out)
            _write_once(target, built_in_inventory(args.revision), args.force)
            print(f"[bom] wrote {target}")
            return 0
        if args.command in {"import-cyclonedx", "import-spdx"}:
            source = _read_json(Path(args.source), MAX_INVENTORY_BYTES)
            inventory = (
                import_cyclonedx(source, inventory_id=args.inventory_id)
                if args.command == "import-cyclonedx"
                else import_spdx(source, inventory_id=args.inventory_id)
            )
            _write_once(Path(args.out), inventory, args.force)
            print(f"[bom] wrote {args.out}; owner enrichment required before decision use")
            return 0
        if args.command == "import-slsa":
            source = _read_json(Path(args.source), MAX_INVENTORY_BYTES)
            report = build_slsa_import_report(source, inventory_id=args.inventory_id)
            inventory_path, report_path = Path(args.out), Path(args.report_out)
            _require_writable_targets((inventory_path, report_path), force=args.force)
            _write_json(inventory_path, report["inventory"])
            _write_json(report_path, report)
            print(
                f"[bom] wrote {inventory_path} and {report_path}; "
                "signature verification and owner enrichment required"
            )
            return 0
        if args.command == "verify-slsa-import":
            report = _read_json(Path(args.report), 3 * MAX_INVENTORY_BYTES)
            source = _read_json(Path(args.source), MAX_INVENTORY_BYTES)
            if errors := verify_slsa_import_report(report, source):
                raise ValueError("; ".join(errors))
            print(f"[bom] verified privacy-minimized SLSA import {args.report}")
            return 0
        if args.command == "import-mlbom":
            source = _read_json(Path(args.source), MAX_INVENTORY_BYTES)
            report = build_mlbom_import_report(source, inventory_id=args.inventory_id)
            inventory_path, report_path = Path(args.out), Path(args.report_out)
            _require_writable_targets((inventory_path, report_path), force=args.force)
            _write_json(inventory_path, report["inventory"])
            _write_json(report_path, report)
            print(
                f"[bom] wrote {inventory_path} and {report_path}; "
                "disclosure presence is not adequacy and owner review is required"
            )
            return 0
        if args.command == "verify-mlbom-import":
            report = _read_json(Path(args.report), 3 * MAX_INVENTORY_BYTES)
            source = _read_json(Path(args.source), MAX_INVENTORY_BYTES)
            if errors := verify_mlbom_import_report(report, source):
                raise ValueError("; ".join(errors))
            print(f"[bom] verified privacy-minimized ML-BOM disclosure import {args.report}")
            return 0
        if args.command == "import-spdx-ai":
            source = _read_json(Path(args.source), MAX_INVENTORY_BYTES)
            report = build_spdx_ai_import_report(source, inventory_id=args.inventory_id)
            inventory_path, report_path = Path(args.out), Path(args.report_out)
            _require_writable_targets((inventory_path, report_path), force=args.force)
            _write_json(inventory_path, report["inventory"])
            _write_json(report_path, report)
            print(
                f"[bom] wrote {inventory_path} and {report_path}; "
                "full SPDX validation and owner review are required"
            )
            return 0
        if args.command == "verify-spdx-ai-import":
            report = _read_json(Path(args.report), 3 * MAX_INVENTORY_BYTES)
            source = _read_json(Path(args.source), MAX_INVENTORY_BYTES)
            if errors := verify_spdx_ai_import_report(report, source):
                raise ValueError("; ".join(errors))
            print(f"[bom] verified privacy-minimized SPDX AI import {args.report}")
            return 0
        if args.command == "compare":
            baseline = _read_json(Path(args.baseline), MAX_INVENTORY_BYTES)
            candidate = _read_json(Path(args.candidate), MAX_INVENTORY_BYTES)
            for label, inventory in (("baseline", baseline), ("candidate", candidate)):
                errors = validate_inventory(inventory)
                if errors:
                    raise ValueError(f"invalid {label}: " + "; ".join(errors))
            report = analyze_change(baseline, candidate, change_reason=args.reason)
            _write_json(Path(args.json_out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), report_to_sarif(report))
            print(f"[bom] {report['summary']['status']}: wrote {args.json_out}")
            return int(
                args.fail_on_reevaluation and report["summary"]["status"] != "no_material_change"
            )
        if args.command == "verify":
            report = _read_json(Path(args.report), 3 * MAX_INVENTORY_BYTES)
            errors = verify_report(report)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[bom] verified {args.report}")
            return 0
        if args.command == "demo":
            destination = Path(args.out_dir)
            if destination.exists() and any(destination.iterdir()) and not args.force:
                raise ValueError(f"output directory is not empty: {destination} (use --force)")
            baseline = built_in_inventory("baseline")
            candidate = built_in_inventory("candidate")
            equivalent = built_in_inventory("equivalent")
            changed = analyze_change(
                baseline, candidate, change_reason="fictional MCP server revision"
            )
            unchanged = analyze_change(baseline, equivalent, change_reason="no content change")
            for name, payload in (
                ("baseline.agentbom.json", baseline),
                ("candidate.agentbom.json", candidate),
                ("changed.claim-impact.json", changed),
                ("changed.claim-impact.sarif", report_to_sarif(changed)),
                ("unchanged.claim-impact.json", unchanged),
            ):
                _write_json(destination / name, payload)
            print(
                f"[bom] changed={changed['summary']['status']} "
                f"unchanged={unchanged['summary']['status']}"
            )
            return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[bom] {args.command} failed: {exc}", file=sys.stderr)
        return 2
    return 0


def _read_json(path: Path, maximum: int) -> dict[str, Any]:
    if path.stat().st_size > maximum:
        raise ValueError(f"input exceeds {maximum} bytes")
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write_once(path: Path, payload: Any, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} exists (use --force)")
    _write_json(path, payload)


def _require_writable_targets(paths: tuple[Path, ...], *, force: bool) -> None:
    if not force and (existing := [str(path) for path in paths if path.exists()]):
        raise FileExistsError(f"output exists (use --force): {', '.join(existing)}")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
