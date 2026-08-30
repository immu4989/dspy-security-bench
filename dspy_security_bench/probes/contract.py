"""Data-only probe manifests and native-verifier conformance checks.

Probe manifests never point to executable entry points. Conformance reads two
bounded local JSON fixtures and delegates semantic verification to an evidence
kind already built into DSPy Security Bench. Supporting a new kind therefore
requires a reviewed implementation change; a manifest cannot load code.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.continuous.proof import build_evidence_snapshot
from dspy_security_bench.mission.loader import canonical_sha256

MANIFEST_TYPE = "dspy-security-bench-probe-manifest"
PROTOCOL_VERSION = "assurance-probe-contract-v1"
MAX_MANIFEST_BYTES = 1_000_000
MAX_FIXTURE_BYTES = 50_000_000
CLAIM_BOUNDARY = (
    "A probe manifest declares local fixtures for an evidence verifier already implemented in "
    "DSPy Security Bench. It never loads contributor code, invokes a model, accesses a network, "
    "accepts secrets, or targets a production system. Passing conformance establishes bounded "
    "format and recomputation compatibility only; it is not proof of observation truth, safety, "
    "compliance, certification, deployment approval, or government endorsement."
)
PROHIBITED_DATA_CLASSES = (
    "credentials-or-secrets",
    "live-target-identifiers",
    "personal-or-regulated-data",
    "production-telemetry",
    "weaponized-exploit-payloads",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = {
    "schema_version",
    "manifest_type",
    "protocol_version",
    "probe_id",
    "name",
    "description",
    "probe_version",
    "maintainer",
    "license",
    "evidence_contract",
    "fixtures",
    "execution_boundary",
    "prohibited_data_classes",
    "claim_boundary",
    "manifest_sha256",
}
_EVIDENCE_FIELDS = {"evidence_kind", "report_type", "native_verifier_required"}
_FIXTURE_FIELDS = {"favorable", "unfavorable"}
_FIXTURE_ITEM_FIELDS = {"path", "expected_sha256", "declared_role"}
_BOUNDARY_FIELDS = {
    "manifest_only",
    "repository_auto_exec",
    "network_access",
    "production_targets",
    "accepts_secrets",
    "third_party_code_loading",
    "max_fixture_bytes",
}


def protocol_payload() -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "manifest_type": MANIFEST_TYPE,
        "conformance_steps": [
            "validate exact manifest structure and content digest",
            "confine fixture paths beneath an explicit local root",
            "enforce fixture byte bounds and canonical digest pins",
            "recompute both fixtures with an existing native verifier",
            "require favorable and unfavorable fixtures to be distinct",
        ],
        "execution_policy": "data-only; third-party code loading and repository auto-execution are forbidden",
        "prohibited_data_classes": list(PROHIBITED_DATA_CLASSES),
        "claim_boundary": CLAIM_BOUNDARY,
    }


def seal_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _clone(manifest)
    normalized.pop("manifest_sha256", None)
    normalized["manifest_sha256"] = canonical_sha256(normalized)
    return normalized


def build_manifest(
    *,
    probe_id: str,
    name: str,
    evidence_kind: str,
    report_type: str,
    favorable_fixture: str,
    unfavorable_fixture: str,
    favorable_sha256: str = "0" * 64,
    unfavorable_sha256: str = "0" * 64,
) -> dict[str, Any]:
    """Return an editable manifest with safe, frozen execution boundaries."""

    payload = {
        "schema_version": 1,
        "manifest_type": MANIFEST_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "probe_id": probe_id,
        "name": name,
        "description": (
            "Replace this description with the bounded behavior measured by the native verifier."
        ),
        "probe_version": "0.1.0",
        "maintainer": "replace-with-accountable-maintainer",
        "license": "Apache-2.0",
        "evidence_contract": {
            "evidence_kind": evidence_kind,
            "report_type": report_type,
            "native_verifier_required": True,
        },
        "fixtures": {
            "favorable": {
                "path": favorable_fixture,
                "expected_sha256": favorable_sha256,
                "declared_role": "supports-the-proposed-claim-under-the-fixture-boundary",
            },
            "unfavorable": {
                "path": unfavorable_fixture,
                "expected_sha256": unfavorable_sha256,
                "declared_role": "challenges-the-proposed-claim-under-the-fixture-boundary",
            },
        },
        "execution_boundary": {
            "manifest_only": True,
            "repository_auto_exec": False,
            "network_access": "denied",
            "production_targets": False,
            "accepts_secrets": False,
            "third_party_code_loading": False,
            "max_fixture_bytes": MAX_FIXTURE_BYTES,
        },
        "prohibited_data_classes": list(PROHIBITED_DATA_CLASSES),
        "claim_boundary": CLAIM_BOUNDARY,
    }
    return seal_manifest(payload)


def validate_manifest(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(manifest, Mapping):
        return ("manifest must be an object",)
    _exact_keys(manifest, _FIELDS, "manifest", errors)
    if (
        manifest.get("schema_version") != 1
        or manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("manifest metadata does not match assurance probe contract v1")
    probe_id = manifest.get("probe_id")
    if not isinstance(probe_id, str) or not _ID.fullmatch(probe_id) or len(probe_id) > 100:
        errors.append("probe_id must be a lowercase kebab-case identifier")
    for field, maximum in (
        ("name", 200),
        ("description", 1_000),
        ("maintainer", 300),
        ("license", 100),
    ):
        _string(manifest.get(field), field, maximum, errors)
    version = manifest.get("probe_version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        errors.append("probe_version must be a semantic version")
    contract = manifest.get("evidence_contract")
    if not isinstance(contract, Mapping):
        errors.append("evidence_contract must be an object")
    else:
        _exact_keys(contract, _EVIDENCE_FIELDS, "evidence_contract", errors)
        _string(contract.get("evidence_kind"), "evidence_contract.evidence_kind", 100, errors)
        _string(contract.get("report_type"), "evidence_contract.report_type", 300, errors)
        if contract.get("native_verifier_required") is not True:
            errors.append("evidence_contract.native_verifier_required must be true")
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, Mapping):
        errors.append("fixtures must be an object")
    else:
        _exact_keys(fixtures, _FIXTURE_FIELDS, "fixtures", errors)
        for role in ("favorable", "unfavorable"):
            fixture = fixtures.get(role)
            label = f"fixtures.{role}"
            if not isinstance(fixture, Mapping):
                errors.append(f"{label} must be an object")
                continue
            _exact_keys(fixture, _FIXTURE_ITEM_FIELDS, label, errors)
            _relative_path(fixture.get("path"), f"{label}.path", errors)
            digest = fixture.get("expected_sha256")
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                errors.append(f"{label}.expected_sha256 must be a SHA-256 digest")
            expected_role = (
                "supports-the-proposed-claim-under-the-fixture-boundary"
                if role == "favorable"
                else "challenges-the-proposed-claim-under-the-fixture-boundary"
            )
            if fixture.get("declared_role") != expected_role:
                errors.append(f"{label}.declared_role does not match the frozen role")
    boundary = manifest.get("execution_boundary")
    expected_boundary = {
        "manifest_only": True,
        "repository_auto_exec": False,
        "network_access": "denied",
        "production_targets": False,
        "accepts_secrets": False,
        "third_party_code_loading": False,
        "max_fixture_bytes": MAX_FIXTURE_BYTES,
    }
    if not isinstance(boundary, Mapping):
        errors.append("execution_boundary must be an object")
    else:
        _exact_keys(boundary, _BOUNDARY_FIELDS, "execution_boundary", errors)
        if dict(boundary) != expected_boundary:
            errors.append("execution_boundary must match the frozen non-executing boundary")
    if manifest.get("prohibited_data_classes") != list(PROHIBITED_DATA_CLASSES):
        errors.append("prohibited_data_classes must match the frozen list")
    if manifest.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match the probe contract")
    claimed = manifest.get("manifest_sha256")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("manifest_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("manifest is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def run_conformance(manifest: Mapping[str, Any], fixture_root: str | Path) -> dict[str, Any]:
    """Recompute two local fixtures without loading or executing contributor code."""

    errors = validate_manifest(manifest)
    if errors:
        raise ValueError("invalid probe manifest: " + "; ".join(errors))
    root = Path(fixture_root).resolve()
    contract = manifest["evidence_contract"]
    results = []
    for role in ("favorable", "unfavorable"):
        declared = manifest["fixtures"][role]
        path = _confined_path(root, declared["path"])
        if not path.is_file():
            raise ValueError(f"{role} fixture is missing: {declared['path']}")
        if path.stat().st_size > MAX_FIXTURE_BYTES:
            raise ValueError(f"{role} fixture exceeds {MAX_FIXTURE_BYTES} bytes")
        payload = json.loads(path.read_text())
        if not isinstance(payload, dict):
            raise ValueError(f"{role} fixture JSON root must be an object")
        actual_sha256 = canonical_sha256(payload)
        if actual_sha256 != declared["expected_sha256"]:
            raise ValueError(f"{role} fixture digest does not match expected_sha256")
        snapshot = build_evidence_snapshot(payload, label=f"{manifest['probe_id']}:{role}")
        if snapshot["evidence_kind"] != contract["evidence_kind"]:
            raise ValueError(
                f"{role} fixture is {snapshot['evidence_kind']!r}, expected "
                f"{contract['evidence_kind']!r}"
            )
        if payload.get("report_type") != contract["report_type"]:
            raise ValueError(f"{role} fixture report_type does not match the manifest")
        results.append(
            {
                "role": role,
                "path": declared["path"],
                "evidence_kind": snapshot["evidence_kind"],
                "report_type": payload["report_type"],
                "canonical_sha256": actual_sha256,
                "native_verifier": "passed",
            }
        )
    if results[0]["canonical_sha256"] == results[1]["canonical_sha256"]:
        raise ValueError("favorable and unfavorable fixtures must be distinct")
    report = {
        "schema_version": 1,
        "report_type": "Assurance probe manifest conformance",
        "protocol_version": PROTOCOL_VERSION,
        "manifest_sha256": manifest["manifest_sha256"],
        "probe_id": manifest["probe_id"],
        "status": "conformant",
        "checks": results,
        "third_party_code_loaded": False,
        "network_requests": 0,
        "production_actions": 0,
        "claim_boundary": CLAIM_BOUNDARY,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def _confined_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("fixture path escapes the declared root")
    return candidate


def _relative_path(value: Any, label: str, errors: list[str]) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1_000
        or Path(value).is_absolute()
        or ".." in Path(value).parts
    ):
        errors.append(f"{label} must be a bounded local relative path")


def _exact_keys(
    value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]
) -> None:
    missing, extra = sorted(expected - set(value)), sorted(set(value) - expected)
    if missing:
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra:
        errors.append(f"{label} has unsupported fields: {', '.join(extra)}")


def _string(value: Any, label: str, maximum: int, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        errors.append(f"{label} must be a non-empty string of at most {maximum} characters")


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
