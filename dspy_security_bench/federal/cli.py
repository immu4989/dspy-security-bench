"""Command-line interface for FederalProof assessment evidence packs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from dspy_security_bench.federal.pack import (
    compare_federal_packs,
    export_federal_pack,
    remove_generated_pack,
    verify_federal_pack,
)
from dspy_security_bench.federal.profile import (
    load_federal_profile,
    profile_template,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench federal",
        description=(
            "Turn verified ProofRun evidence into OSCAL 1.2.2 assessment inputs, "
            "an impact-assessment annex, and a QASP scorecard."
        ),
    )
    commands = parser.add_subparsers(dest="command")

    init = commands.add_parser("init", help="create a FederalProof deployment profile")
    init.add_argument("--out", default="federal-profile.yaml")
    init.add_argument("--force", action="store_true")

    validate = commands.add_parser("profile-validate", help="validate a deployment profile")
    validate.add_argument("profile")

    export = commands.add_parser("export", help="export a content-addressed evidence pack")
    export.add_argument("evidence", help="ProofRun impact or control bundle")
    export.add_argument("--profile", required=True)
    export.add_argument("--out-dir", required=True)
    export.add_argument("--force", action="store_true")

    verify = commands.add_parser("verify", help="recompute a FederalProof pack offline")
    verify.add_argument("pack")

    compare = commands.add_parser("compare", help="compare two or more verified packs")
    compare.add_argument("packs", nargs="+")
    compare.add_argument("--json-out")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "init":
        return _init(args)
    if args.command == "profile-validate":
        return _validate(args)
    if args.command == "export":
        return _export(args)
    if args.command == "verify":
        return _verify(args)
    if args.command == "compare":
        return _compare(args)
    return 2


def _init(args) -> int:
    path = Path(args.out)
    if path.exists() and not args.force:
        print(f"[federal] kept existing {path} (use --force to replace)", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(profile_template(), sort_keys=False))
    print(f"[federal] created {path}")
    print("[federal] replace every REPLACE value and .example URI before export")
    return 0


def _validate(args) -> int:
    try:
        profile = load_federal_profile(args.profile)
    except ValueError as exc:
        print(f"[INVALID] {exc}", file=sys.stderr)
        return 2
    print(f"[VALID] {args.profile}: {profile.system['system_id']}")
    return 0


def _export(args) -> int:
    try:
        profile = load_federal_profile(args.profile)
        destination = Path(args.out_dir)
        if args.force and destination.exists() and any(destination.iterdir()):
            remove_generated_pack(destination)
        manifest = export_federal_pack(
            args.evidence,
            profile,
            destination,
            force=False,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"[federal] export failed: {exc}", file=sys.stderr)
        return 2
    print(f"[federal] wrote {args.out_dir}")
    print(f"[federal] result: {manifest['overall_result']}")
    print(f"[federal] pack sha256: {manifest['pack_sha256']}")
    print(f"[federal] POA&M: {manifest['poam_status']}")
    return 0 if manifest["overall_result"] == "pass" else 1


def _verify(args) -> int:
    result = verify_federal_pack(args.pack)
    print(f"Integrity: {'valid' if result.valid else 'INVALID'}")
    if result.overall_result:
        print(f"Local performance objectives: {result.overall_result}")
    if result.pack_sha256:
        print(f"Pack sha256: {result.pack_sha256}")
    for error in result.errors:
        print(f"  error: {error}")
    for warning in result.warnings:
        print(f"  note: {warning}")
    return 0 if result.valid else 2


def _compare(args) -> int:
    try:
        comparison = compare_federal_packs(args.packs)
    except ValueError as exc:
        print(f"[federal] compare failed: {exc}", file=sys.stderr)
        return 2
    if args.json_out:
        path = Path(args.json_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n")
    for candidate in comparison["candidates"]:
        passed = sum(item["status"] == "pass" for item in candidate["objectives"].values())
        total = len(candidate["objectives"])
        print(
            f"{candidate['agent']}: {candidate['overall_result']} "
            f"({passed}/{total} local objectives passed)"
        )
    print(f"note: {comparison['disclaimer']}")
    return 0
