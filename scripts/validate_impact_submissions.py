#!/usr/bin/env python3
"""Validate every committed community evidence submission."""

from __future__ import annotations

import re
from pathlib import Path

from dspy_security_bench.authority.repeat import BUNDLE_TYPE as AUTHORITY_BUNDLE_TYPE
from dspy_security_bench.authority.repeat import verify_authority_submission_bundle
from dspy_security_bench.causal.registry import BUNDLE_TYPE as CAUSAL_BUNDLE_TYPE
from dspy_security_bench.causal.registry import verify_causal_submission_bundle
from dspy_security_bench.collective.registry import BUNDLE_TYPE as COLLECTIVE_BUNDLE_TYPE
from dspy_security_bench.collective.registry import verify_collective_submission_bundle
from dspy_security_bench.defend.evidence import BUNDLE_TYPE as DEFENSE_BUNDLE_TYPE
from dspy_security_bench.defend.evidence import verify_evidence_bundle
from dspy_security_bench.incident.repeat import BUNDLE_TYPE as INCIDENT_BUNDLE_TYPE
from dspy_security_bench.incident.repeat import verify_incident_submission_bundle
from dspy_security_bench.jsonio import read_json_snapshot
from dspy_security_bench.mission.repeat import BUNDLE_TYPE as SOURCE_BUNDLE_TYPE
from dspy_security_bench.mission.repeat import verify_source_submission_bundle
from dspy_security_bench.procurement.control_registry import (
    BUNDLE_TYPE as CONTROL_BUNDLE_TYPE,
)
from dspy_security_bench.procurement.control_registry import (
    verify_control_submission_bundle,
)
from dspy_security_bench.procurement.registry_metadata import (
    attestation_record_errors,
    registry_shape,
    reproduction_record_errors,
)
from dspy_security_bench.procurement.repeat import verify_submission_bundle
from dspy_security_bench.proofrun import verify_github_attestation
from dspy_security_bench.trace.evidence import BUNDLE_TYPE as TRACE_BUNDLE_TYPE
from dspy_security_bench.trace.evidence import verify_trace_submission_bundle

MAX_SUBMISSIONS = 1000
MAX_BUNDLE_BYTES = 50_000_000
MAX_TOTAL_BYTES = 250_000_000
MAX_REGISTRY_BYTES = 5_000_000
FAMILY_TYPES = {
    "impact": "dspy-security-bench-community-submission",
    "control": CONTROL_BUNDLE_TYPE, "incident": INCIDENT_BUNDLE_TYPE,
    "source": SOURCE_BUNDLE_TYPE, "authority": AUTHORITY_BUNDLE_TYPE,
    "trace": TRACE_BUNDLE_TYPE, "causal": CAUSAL_BUNDLE_TYPE,
    "collective": COLLECTIVE_BUNDLE_TYPE, "defense": DEFENSE_BUNDLE_TYPE,
}
INTAKE_ERRORS = (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError)


def _ordinary_path(root: Path, path: Path, *, directory: bool = False) -> None:
    relative = path.relative_to(root)
    if ".." in relative.parts:
        raise ValueError("input escapes checkout")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("linked input paths are not supported")
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError("input must be an ordinary directory or file")


def _read_input(root: Path, path: Path, limit: int) -> tuple[bytes, dict]:
    _ordinary_path(root, path)
    return read_json_snapshot(path, limit)


def _discover(root: Path) -> tuple[list[Path], bool]:
    paths, failed, total = [], False, 0
    for family in FAMILY_TYPES:
        directory = root / "submissions" / family
        try:
            # A missing category is empty; dangling links must not masquerade as missing.
            if not directory.exists() and not directory.is_symlink():
                continue
            _ordinary_path(root, directory, directory=True)
            for path in directory.glob("*.json"):
                paths.append(path)
                if len(paths) > MAX_SUBMISSIONS:
                    raise OverflowError("submission count budget exceeded")
                if not path.is_symlink() and path.is_file():
                    total += path.stat().st_size
                if total > MAX_TOTAL_BYTES:
                    raise OverflowError("aggregate input budget exceeded")
        except OverflowError:
            print("[INVALID] submission count or aggregate byte budget exceeded")
            return [], True
        except INTAKE_ERRORS:
            print(f"[INVALID] submissions/{family}: invalid input directory; source details withheld")
            failed = True
    return sorted(paths), failed


def main(root: Path | None = None) -> int:
    root = Path(__file__).resolve().parents[1] if root is None else Path(root).resolve()
    submissions, failed = _discover(root)
    if not submissions:
        print("[submissions] no readable JSON submission candidates")
    accepted_bundles: dict[str, dict] = {}
    authenticated_bundles: dict[str, dict] = {}
    verifiers = {
        "impact": verify_submission_bundle, "control": verify_control_submission_bundle,
        "incident": verify_incident_submission_bundle, "source": verify_source_submission_bundle,
        "authority": verify_authority_submission_bundle, "trace": verify_trace_submission_bundle,
        "causal": verify_causal_submission_bundle, "collective": verify_collective_submission_bundle,
        "defense": verify_evidence_bundle,
    }
    for path in submissions:
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*\.json", path.name):
            print("[INVALID] submission filename must be lowercase kebab-case; source name withheld")
            failed = True
            continue
        try:
            raw, bundle = _read_input(root, path, MAX_BUNDLE_BYTES)
            family = path.parent.name
            if bundle.get("bundle_type") != FAMILY_TYPES[family]:
                raise ValueError("bundle type does not match submission directory")
            result = verifiers[family](bundle)
            eligible = result.registry_eligible if family == "control" else result.community_eligible
            if result.errors or not getattr(result, "valid", True):
                raise ValueError("native verification failed")
            if not eligible:
                print(f"[NOT ELIGIBLE] {path.relative_to(root)}")
                failed = True
                continue
            digest = bundle.get("bundle_sha256")
            if not _is_digest(digest):
                raise ValueError("bundle digest is missing or malformed")
            provenance = bundle.get("provenance")
            authenticated = False
            if isinstance(provenance, dict) and provenance.get("provider") == "github_actions":
                attestation = verify_github_attestation(path, bundle, bundle_bytes=raw)
                if not attestation.verified:
                    print(f"[UNVERIFIED PROVENANCE] {path.relative_to(root)}")
                    failed = True
                    continue
                authenticated = True
        except INTAKE_ERRORS:
            print(f"[INVALID] {path.relative_to(root)}: input or native verification failed; source details withheld")
            failed = True
            continue
        marker = "CRYPTOGRAPHICALLY VERIFIED" if authenticated else "NATIVE VALID AND ELIGIBLE"
        print(f"[{marker}] {path.relative_to(root)}")
        accepted_bundles[digest] = bundle
        if authenticated:
            authenticated_bundles[digest] = bundle
    failed = _validate_attestations(root, authenticated_bundles) or failed
    failed = _validate_reproductions(root, set(accepted_bundles)) or failed
    return 1 if failed else 0


def _validate_attestations(root: Path, authenticated_bundles: dict[str, dict]) -> bool:
    """Check declarations only against bundles authenticated during this run."""
    path = root / "submissions" / "attestations.json"
    try:
        _, registry = _read_input(root, path, MAX_REGISTRY_BYTES)
    except INTAKE_ERRORS:
        print("[INVALID] submissions/attestations.json: invalid input; source details withheld")
        return True
    if not registry_shape(registry, "attestations"):
        print("[INVALID] submissions/attestations.json: unsupported registry shape")
        return True
    failed = False
    for digest, record in registry["attestations"].items():
        if not _is_digest(digest):
            print("[INVALID] attestation registry key must be lowercase SHA-256; source key withheld")
            failed = True
            continue
        bundle = authenticated_bundles.get(digest)
        provenance = bundle.get("provenance") if isinstance(bundle, dict) else None
        if not isinstance(provenance, dict) or provenance.get("provider") != "github_actions":
            print(f"[INVALID] attestation {digest}: no cryptographically accepted bundle")
            failed = True
            continue
        for error in attestation_record_errors(record, provenance):
            print(f"[INVALID] attestation {digest}: {error}")
            failed = True
    return failed


def _validate_reproductions(root: Path, accepted_digests: set[str]) -> bool:
    path = root / "submissions" / "reproductions.json"
    try:
        _, registry = _read_input(root, path, MAX_REGISTRY_BYTES)
    except INTAKE_ERRORS:
        print("[INVALID] submissions/reproductions.json: invalid input; source details withheld")
        return True
    if not registry_shape(registry, "reproductions"):
        print("[INVALID] submissions/reproductions.json: unsupported registry shape")
        return True
    failed = False
    for digest, reproduction in registry["reproductions"].items():
        if not _is_digest(digest):
            print("[INVALID] reproduction registry key must be lowercase SHA-256; source key withheld")
            failed = True
            continue
        if digest not in accepted_digests:
            print(f"[INVALID] reproduction {digest}: no accepted submission has this digest")
            failed = True
        for error in reproduction_record_errors(reproduction):
            print(f"[INVALID] reproduction {digest}: {error}")
            failed = True
    return failed


def _is_digest(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


if __name__ == "__main__":
    raise SystemExit(main())
