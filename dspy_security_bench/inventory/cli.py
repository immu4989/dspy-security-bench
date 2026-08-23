"""InventoryForge command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from dspy_security_bench.inventory.forge import draft_mission_pack
from dspy_security_bench.inventory.loader import (
    find_use_case,
    load_inventory_report,
    load_public_inventory,
    verify_inventory_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench inventory",
        description=(
            "Normalize public AI use-case inventories and create synthetic, human-reviewed MissionPack drafts."
        ),
    )
    commands = parser.add_subparsers(dest="command")
    import_command = commands.add_parser("import", help="normalize a local public CSV or JSON")
    import_command.add_argument("source")
    import_command.add_argument("--out", required=True)
    import_command.add_argument("--force", action="store_true")
    list_command = commands.add_parser("list", help="list normalized use cases")
    list_command.add_argument("inventory")
    draft = commands.add_parser("draft-pack", help="create a synthetic MissionPack draft")
    draft.add_argument("inventory")
    draft.add_argument("use_case_id")
    draft.add_argument("--out", required=True)
    draft.add_argument("--manifest-out")
    draft.add_argument("--force", action="store_true")
    verify = commands.add_parser("verify", help="recompute normalized report integrity")
    verify.add_argument("inventory")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "import":
        return _import(args)
    if args.command == "list":
        return _list(args)
    if args.command == "draft-pack":
        return _draft(args)
    if args.command == "verify":
        return _verify(args)
    return 2


def _import(args) -> int:
    destination = Path(args.out)
    if destination.exists() and not args.force:
        print(f"[inventory] kept existing {destination}; use --force to replace", file=sys.stderr)
        return 1
    try:
        report = load_public_inventory(args.source).to_dict()
        _write_json(destination, report)
    except (OSError, TypeError, ValueError) as exc:
        print(f"[inventory] import failed: {exc}", file=sys.stderr)
        return 2
    print(f"[inventory] normalized {report['record_count']} public use cases")
    print(f"[inventory] wrote {args.out}: {report['report_sha256']}")
    for warning in report["warnings"]:
        print(f"  note: {warning}")
    return 0


def _list(args) -> int:
    try:
        payload = load_inventory_report(args.inventory)
    except ValueError as exc:
        print(f"[INVALID] {exc}", file=sys.stderr)
        return 2
    for item in payload["records"]:
        print(f"{item['use_case_id']}  {item['agency']}  {item['name']}")
    return 0


def _draft(args) -> int:
    destination = Path(args.out)
    manifest_path = Path(args.manifest_out or f"{args.out}.inventory.json")
    if not args.force and (destination.exists() or manifest_path.exists()):
        print("[inventory] kept existing output; use --force to replace", file=sys.stderr)
        return 1
    try:
        payload = load_inventory_report(args.inventory)
        record = find_use_case(payload, args.use_case_id)
        pack, manifest = draft_mission_pack(record)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(yaml.safe_dump(pack.raw, sort_keys=False), encoding="utf-8")
        _write_json(manifest_path, manifest)
    except (OSError, TypeError, ValueError) as exc:
        print(f"[inventory] draft failed: {exc}", file=sys.stderr)
        return 2
    print(f"[inventory] wrote human-review-required draft {destination}")
    print(f"[inventory] wrote provenance {manifest_path}")
    print(f"Next: dspy-security-bench pack validate {destination}")
    return 0


def _verify(args) -> int:
    try:
        payload = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
        errors = verify_inventory_report(payload) if isinstance(payload, dict) else ("root",)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"[INVALID] {exc}", file=sys.stderr)
        return 2
    print(f"Integrity: {'valid' if not errors else 'INVALID'}")
    for error in errors:
        print(f"  error: {error}")
    return 0 if not errors else 2


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
