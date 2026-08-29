"""Data-only adapter conformance for the DefenderTwin proposal contract."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any
from urllib.parse import urlparse

from dspy_security_bench.defend.protocol import SECTORS, validate_mission, validate_proposal
from dspy_security_bench.mission.loader import canonical_sha256

MANIFEST_TYPE = "dspy-security-bench-defender-adapter-manifest"
REPORT_TYPE = "DefenderTwin / Adapter contract conformance"
DISCLAIMER = (
    "Adapter conformance validates a data contract and frozen fixture output. It does not execute "
    "or endorse the adapter, authenticate its maintainer, prove production behavior, or certify safety."
)


def adapter_manifest_template() -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "manifest_type": MANIFEST_TYPE,
        "adapter_id": "defendertwin-reference",
        "adapter_version": "v1",
        "framework": "data-only",
        "input_contract": "defense-mission-v1",
        "output_contract": "remediation-proposal-v1",
        "execution_boundary": "synthetic-twin-no-live-target-actions",
        "content_fields_processed": 0,
        "supported_sectors": list(SECTORS),
        "source_repository": "https://github.com/immu4989/dspy-security-bench/tree/main",
        "known_gaps": ["reference-fixture-only"],
        "claim_boundary": DISCLAIMER,
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest


def validate_adapter_manifest(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "manifest_type",
        "adapter_id",
        "adapter_version",
        "framework",
        "input_contract",
        "output_contract",
        "execution_boundary",
        "content_fields_processed",
        "supported_sectors",
        "source_repository",
        "known_gaps",
        "claim_boundary",
        "manifest_sha256",
    }
    if set(manifest) != fields:
        errors.append("adapter manifest fields are incomplete or unsupported")
    if manifest.get("schema_version") != 1 or manifest.get("manifest_type") != MANIFEST_TYPE:
        errors.append("adapter manifest metadata is unsupported")
    for field in ("adapter_id", "adapter_version", "framework"):
        if (
            not isinstance(manifest.get(field), str)
            or not manifest[field].strip()
            or len(manifest[field]) > 120
        ):
            errors.append(f"{field} must be a bounded non-empty string")
    if manifest.get("input_contract") != "defense-mission-v1":
        errors.append("input_contract is unsupported")
    if manifest.get("output_contract") != "remediation-proposal-v1":
        errors.append("output_contract is unsupported")
    if manifest.get("execution_boundary") != "synthetic-twin-no-live-target-actions":
        errors.append("execution_boundary must prohibit live target actions")
    if manifest.get("content_fields_processed") != 0:
        errors.append("content_fields_processed must be zero")
    sectors = manifest.get("supported_sectors")
    if (
        not isinstance(sectors, list)
        or not sectors
        or not all(isinstance(item, str) for item in sectors)
        or len(sectors) != len(set(item for item in sectors if isinstance(item, str)))
        or any(item not in SECTORS for item in sectors)
    ):
        errors.append("supported_sectors must contain known sector identifiers")
    parsed = urlparse(str(manifest.get("source_repository", "")))
    if parsed.scheme != "https" or not parsed.netloc:
        errors.append("source_repository must be an https URL")
    gaps = manifest.get("known_gaps")
    if (
        not isinstance(gaps, list)
        or not gaps
        or not all(isinstance(item, str) and item.strip() and len(item) <= 300 for item in gaps)
    ):
        errors.append("known_gaps must contain bounded non-empty strings")
    if manifest.get("claim_boundary") != DISCLAIMER:
        errors.append("adapter claim boundary changed")
    try:
        unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        if manifest.get("manifest_sha256") != canonical_sha256(unsigned):
            errors.append("manifest_sha256 does not match canonical manifest content")
    except (TypeError, ValueError):
        errors.append("adapter manifest is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def test_adapter(
    manifest: Mapping[str, Any], mission: Mapping[str, Any], proposal: Mapping[str, Any]
) -> dict[str, Any]:
    manifest_errors = validate_adapter_manifest(manifest)
    mission_errors = validate_mission(mission)
    proposal_errors = validate_proposal(proposal, mission) if not mission_errors else ()
    binding_errors = []
    adapter = proposal.get("adapter") if isinstance(proposal, Mapping) else None
    if isinstance(adapter, Mapping):
        if adapter.get("adapter_id") != manifest.get("adapter_id"):
            binding_errors.append("proposal adapter_id does not match the manifest")
        if adapter.get("adapter_version") != manifest.get("adapter_version"):
            binding_errors.append("proposal adapter_version does not match the manifest")
        if adapter.get("framework") != manifest.get("framework"):
            binding_errors.append("proposal framework does not match the manifest")
    supported_sectors = manifest.get("supported_sectors")
    if not isinstance(supported_sectors, list) or mission.get("sector") not in supported_sectors:
        binding_errors.append("mission sector is not supported by the manifest")
    all_errors = [*manifest_errors, *mission_errors, *proposal_errors, *binding_errors]
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "manifest": deepcopy(dict(manifest)),
        "mission_sha256": mission.get("mission_sha256"),
        "proposal_sha256": proposal.get("proposal_sha256"),
        "summary": {
            "status": "conformant" if not all_errors else "not-conformant",
            "manifest_valid": not manifest_errors,
            "mission_valid": not mission_errors,
            "proposal_valid": not proposal_errors,
            "adapter_binding_valid": not binding_errors,
            "content_fields_processed": 0,
        },
        "errors": all_errors,
        "claim_boundary": DISCLAIMER,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_conformance_report(
    report: Mapping[str, Any], mission: Mapping[str, Any], proposal: Mapping[str, Any]
) -> tuple[str, ...]:
    manifest = report.get("manifest")
    if not isinstance(manifest, Mapping):
        return ("conformance report manifest must be an object",)
    expected = test_adapter(manifest, mission, proposal)
    return () if report == expected else ("conformance report does not recompute",)
