"""ValueProof command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench value")
    commands = parser.add_subparsers(dest="command")
    init = commands.add_parser("init", help="write an owner-supplied measurement template")
    init.add_argument("--out", default="value-observation.json")
    init.add_argument("--force", action="store_true")
    build = commands.add_parser("build", help="compute a content-addressed ValueProof")
    build.add_argument("measurement")
    build.add_argument("--out", required=True)
    verify = commands.add_parser("verify", help="verify a ValueProof offline")
    verify.add_argument("proof")
    compare = commands.add_parser("compare", help="compare equivalent observations without ranking")
    compare.add_argument("proofs", nargs="+")
    compare.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    from dspy_security_bench.value.proof import (
        build_value_proof,
        compare_value_proofs,
        measurement_template,
        verify_value_proof,
    )

    try:
        if args.command == "init":
            path = Path(args.out)
            if path.exists() and not args.force:
                print(f"[value] kept existing {path} (use --force to replace)", file=sys.stderr)
                return 1
            _write(path, measurement_template())
            print(f"[value] created {path}; replace every template observation before use")
            return 0
        if args.command == "build":
            proof = build_value_proof(_read(args.measurement))
            _write(args.out, proof)
            print(f"[value] wrote {args.out} ({proof['proof_sha256']})")
            return 0
        if args.command == "verify":
            errors = verify_value_proof(_read(args.proof))
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[value] verified {args.proof}")
            return 0
        if args.command == "compare":
            comparison = compare_value_proofs([_read(path) for path in args.proofs])
            _write(args.out, comparison)
            print(f"[value] wrote {args.out}; comparable={str(comparison['comparable']).lower()}")
            return 0 if comparison["comparable"] else 1
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[value] failed: {exc}", file=sys.stderr)
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
