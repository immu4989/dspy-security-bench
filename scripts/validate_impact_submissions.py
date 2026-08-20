#!/usr/bin/env python3
"""Validate every committed Impact, Control, Incident, Source, and Authority submission."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from dspy_security_bench.authority.repeat import BUNDLE_TYPE as AUTHORITY_BUNDLE_TYPE
from dspy_security_bench.authority.repeat import verify_authority_submission_bundle
from dspy_security_bench.incident.repeat import BUNDLE_TYPE as INCIDENT_BUNDLE_TYPE
from dspy_security_bench.incident.repeat import verify_incident_submission_bundle
from dspy_security_bench.mission.repeat import BUNDLE_TYPE as SOURCE_BUNDLE_TYPE
from dspy_security_bench.mission.repeat import verify_source_submission_bundle
from dspy_security_bench.procurement.control_registry import (
    BUNDLE_TYPE as CONTROL_BUNDLE_TYPE,
)
from dspy_security_bench.procurement.control_registry import (
    verify_control_submission_bundle,
)
from dspy_security_bench.procurement.repeat import verify_submission_bundle
from dspy_security_bench.proofrun import TRUSTED_BUILDER_WORKFLOW, verify_github_attestation


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    submissions = [
        *sorted((root / "submissions" / "impact").glob("*.json")),
        *sorted((root / "submissions" / "control").glob("*.json")),
        *sorted((root / "submissions" / "incident").glob("*.json")),
        *sorted((root / "submissions" / "source").glob("*.json")),
        *sorted((root / "submissions" / "authority").glob("*.json")),
    ]
    if not submissions:
        print("[submissions] no JSON submissions committed yet")
    failed = False
    accepted_bundles: dict[str, dict] = {}
    for path in submissions:
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*\.json", path.name):
            print(f"[INVALID] {path.relative_to(root)}: filename must be lowercase kebab-case")
            failed = True
            continue
        try:
            bundle = json.loads(path.read_text())
            if bundle.get("bundle_type") == CONTROL_BUNDLE_TYPE:
                result = verify_control_submission_bundle(bundle)
                eligible = result.registry_eligible
            elif bundle.get("bundle_type") == INCIDENT_BUNDLE_TYPE:
                result = verify_incident_submission_bundle(bundle)
                eligible = result.community_eligible
            elif bundle.get("bundle_type") == SOURCE_BUNDLE_TYPE:
                result = verify_source_submission_bundle(bundle)
                eligible = result.community_eligible
            elif bundle.get("bundle_type") == AUTHORITY_BUNDLE_TYPE:
                result = verify_authority_submission_bundle(bundle)
                eligible = result.community_eligible
            else:
                result = verify_submission_bundle(bundle)
                eligible = result.community_eligible
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            print(f"[INVALID] {path.relative_to(root)}: {exc}")
            failed = True
            continue
        marker = "VERIFIED" if eligible else "NOT ELIGIBLE"
        print(f"[{marker}] {path.relative_to(root)}")
        for error in result.errors:
            print(f"  error: {error}")
        for warning in result.warnings:
            print(f"  note: {warning}")
        provenance = bundle.get("provenance")
        if isinstance(provenance, dict) and provenance.get("provider") == "github_actions":
            attestation = verify_github_attestation(path, bundle)
            print(f"  provenance: {attestation.evidence_tier}")
            for error in attestation.errors:
                print(f"  error: {error}")
            for warning in attestation.warnings:
                print(f"  note: {warning}")
            eligible = eligible and attestation.verified
        if eligible:
            digest = bundle.get("bundle_sha256")
            if isinstance(digest, str):
                accepted_bundles[digest] = bundle
        failed = failed or not eligible
    failed = _validate_attestations(root, accepted_bundles) or failed
    failed = _validate_reproductions(root, set(accepted_bundles)) or failed
    return 1 if failed else 0


def _validate_attestations(root: Path, accepted_bundles: dict[str, dict]) -> bool:
    path = root / "submissions" / "attestations.json"
    try:
        registry = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[INVALID] submissions/attestations.json: {exc}")
        return True
    if registry.get("schema_version") != 1 or not isinstance(registry.get("attestations"), dict):
        print("[INVALID] submissions/attestations.json: unsupported registry shape")
        return True
    failed = False
    for digest, record in registry["attestations"].items():
        bundle = accepted_bundles.get(digest)
        if bundle is None:
            print(f"[INVALID] attestation {digest}: no cryptographically accepted bundle")
            failed = True
            continue
        if not isinstance(record, dict):
            print(f"[INVALID] attestation {digest}: metadata must be an object")
            failed = True
            continue
        required = (
            "evidence_tier",
            "verified_by",
            "verified_at",
            "run_url",
            "source_commit",
            "signer_workflow",
        )
        if any(not str(record.get(field, "")).strip() for field in required):
            print(f"[INVALID] attestation {digest}: incomplete metadata")
            failed = True
        provenance = bundle.get("provenance", {})
        expected_tier = (
            "trusted_builder"
            if provenance.get("builder_kind") == "dspy_security_bench_reusable_workflow"
            else "github_attested"
        )
        comparisons = {
            "evidence_tier": expected_tier,
            "run_url": provenance.get("run_url"),
            "source_commit": provenance.get("commit_sha"),
        }
        for field, expected in comparisons.items():
            if record.get(field) != expected:
                print(f"[INVALID] attestation {digest}: {field} does not match bundle")
                failed = True
        if (
            expected_tier == "trusted_builder"
            and record.get("signer_workflow") != TRUSTED_BUILDER_WORKFLOW
        ):
            print(f"[INVALID] attestation {digest}: unexpected trusted signer workflow")
            failed = True
    return failed


def _validate_reproductions(root: Path, accepted_digests: set[str]) -> bool:
    path = root / "submissions" / "reproductions.json"
    try:
        registry = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[INVALID] submissions/reproductions.json: {exc}")
        return True
    if registry.get("schema_version") != 1 or not isinstance(registry.get("reproductions"), dict):
        print("[INVALID] submissions/reproductions.json: unsupported registry shape")
        return True
    failed = False
    for digest, reproduction in registry["reproductions"].items():
        if digest not in accepted_digests:
            print(f"[INVALID] reproduction {digest}: no accepted submission has this digest")
            failed = True
        if not isinstance(reproduction, dict):
            print(f"[INVALID] reproduction {digest}: metadata must be an object")
            failed = True
            continue
        required = ("reproduced_by", "run_url", "created_at")
        if any(not str(reproduction.get(field, "")).strip() for field in required):
            print(f"[INVALID] reproduction {digest}: incomplete metadata")
            failed = True
        parsed = urlparse(str(reproduction.get("run_url", "")))
        if parsed.scheme != "https" or not parsed.netloc:
            print(f"[INVALID] reproduction {digest}: run_url must use https")
            failed = True
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
