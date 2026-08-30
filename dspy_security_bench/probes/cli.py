"""Command-line interface for declarative assurance probe manifests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dspy_security_bench.continuous.proof import build_evidence_snapshot
from dspy_security_bench.probes.contract import (
    MAX_MANIFEST_BYTES,
    build_manifest,
    protocol_payload,
    run_conformance,
    validate_manifest,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench probe",
        description="Validate data-only probe contributions without loading third-party code.",
    )
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen probe contract")
    describe.add_argument("--json", action="store_true", dest="as_json")
    init = commands.add_parser("init", help="write an editable, non-executing manifest")
    init.add_argument("--probe-id", required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--evidence-kind", required=True)
    init.add_argument("--report-type", required=True)
    init.add_argument("--favorable-fixture", default="fixtures/favorable.json")
    init.add_argument("--unfavorable-fixture", default="fixtures/unfavorable.json")
    init.add_argument("--out", required=True)
    init.add_argument("--force", action="store_true")
    digest = commands.add_parser("digest", help="natively verify a fixture and print its digest")
    digest.add_argument("fixture")
    validate = commands.add_parser("validate", help="validate manifest structure and identity")
    validate.add_argument("manifest")
    conformance = commands.add_parser(
        "conformance", help="recompute both local fixtures through the native verifier"
    )
    conformance.add_argument("manifest")
    conformance.add_argument("--fixture-root", required=True)
    conformance.add_argument("--out")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "describe":
            payload = protocol_payload()
            if args.as_json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print("Assurance probe contract v1 — declarative and non-executing")
                print(payload["execution_policy"])
                print(payload["claim_boundary"])
            return 0
        if args.command == "init":
            payload = build_manifest(
                probe_id=args.probe_id,
                name=args.name,
                evidence_kind=args.evidence_kind,
                report_type=args.report_type,
                favorable_fixture=args.favorable_fixture,
                unfavorable_fixture=args.unfavorable_fixture,
            )
            _write_once(Path(args.out), payload, args.force)
            print(f"[probe] created {args.out}")
            print("[probe] pin both fixtures with: dspy-security-bench probe digest FIXTURE")
            return 0
        if args.command == "digest":
            payload = _read(Path(args.fixture), 50_000_000)
            snapshot = build_evidence_snapshot(payload, label=Path(args.fixture).name)
            print(snapshot["evidence_sha256"])
            return 0
        if args.command == "validate":
            payload = _read(Path(args.manifest), MAX_MANIFEST_BYTES)
            errors = validate_manifest(payload)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[probe] valid manifest: {args.manifest}")
            return 0
        if args.command == "conformance":
            payload = _read(Path(args.manifest), MAX_MANIFEST_BYTES)
            report = run_conformance(payload, args.fixture_root)
            if args.out:
                _write(Path(args.out), report)
            print(
                f"[probe] {report['status']}: two native fixtures verified; "
                "third_party_code_loaded=false"
            )
            return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[probe] {args.command} failed: {exc}", file=sys.stderr)
        return 2
    return 0


def _read(path: Path, maximum: int) -> dict:
    if path.stat().st_size > maximum:
        raise ValueError(f"input exceeds {maximum} bytes")
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write_once(path: Path, payload: dict, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} exists (use --force)")
    _write(path, payload)


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
