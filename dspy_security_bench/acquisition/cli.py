"""AcquisitionProof CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench acquisition")
    commands = parser.add_subparsers(dest="command")
    init = commands.add_parser("init", help="write an owner-editable acquisition profile")
    init.add_argument("--out", default="acquisition-profile.json")
    init.add_argument("--force", action="store_true")
    validate = commands.add_parser("validate", help="validate an acquisition profile")
    validate.add_argument("profile")
    export = commands.add_parser("export", help="export a content-addressed evidence pack")
    export.add_argument("evidence")
    export.add_argument("--profile", required=True)
    export.add_argument("--out", required=True)
    export.add_argument("--force", action="store_true")
    verify = commands.add_parser("verify", help="verify an AcquisitionProof pack offline")
    verify.add_argument("path")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    from dspy_security_bench.acquisition.pack import (
        export_acquisition_pack,
        verify_acquisition_pack,
    )
    from dspy_security_bench.acquisition.profile import (
        example_profile,
        validate_acquisition_profile,
    )

    try:
        if args.command == "init":
            path = Path(args.out)
            if path.exists() and not args.force:
                raise FileExistsError(f"{path} exists (use --force)")
            path.write_text(json.dumps(example_profile(), indent=2, sort_keys=True) + "\n")
            print(f"[acquisition] created {path}")
            return 0
        if args.command == "verify":
            errors = verify_acquisition_pack(args.path)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[acquisition] verified {args.path}")
            return 0
        profile = validate_acquisition_profile(
            _read(args.profile if args.command == "export" else args.profile)
        )
        if args.command == "validate":
            print(f"[acquisition] valid profile {profile.profile_sha256}")
            return 0
        manifest = export_acquisition_pack(
            _read(args.evidence), profile, args.out, force=args.force
        )
        print(f"[acquisition] exported {manifest['pack_sha256']} to {args.out}")
        return 0
    except (FileExistsError, OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[acquisition] failed: {exc}", file=sys.stderr)
        return 2


def _read(path: str) -> dict:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload
