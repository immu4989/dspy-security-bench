"""Shared typed checks for owner-reviewed public tier declarations.

These checks do not authenticate signatures or perform reproductions. Callers
must separately establish bundle eligibility and cryptographic admission.
"""

from datetime import datetime, timezone

from dspy_security_bench.procurement.submission_metadata import _https_reference
from dspy_security_bench.proofrun import TRUSTED_BUILDER_WORKFLOW


def registry_shape(payload, key: str) -> bool:
    return (isinstance(payload, dict) and set(payload) == {"schema_version", key}
            and type(payload.get("schema_version")) is int and payload["schema_version"] == 1
            and isinstance(payload.get(key), dict))


def _record_shape(record, required) -> bool:
    return (isinstance(record, dict) and set(record) == set(required)
            and all(isinstance(record[field], str) and record[field].strip() for field in required))


def _utc_timestamp(value) -> bool:
    if not isinstance(value, str) or not value.endswith("Z") or "T" not in value:
        return False
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").utcoffset() == timezone.utc.utcoffset(None)
    except ValueError:
        return False


def attestation_record_errors(record, provenance) -> tuple[str, ...]:
    required = ("evidence_tier", "verified_by", "verified_at", "run_url", "source_commit", "signer_workflow")
    if not _record_shape(record, required):
        return ("missing, unsupported, or mistyped metadata",)
    if not isinstance(provenance, dict) or provenance.get("provider") != "github_actions":
        return ("GitHub provenance is required for an attestation tier",)
    errors = []
    if not _utc_timestamp(record["verified_at"]) or not _https_reference(record["run_url"]):
        errors.append("invalid timestamp or run URL")
    tier = "trusted_builder" if provenance.get("builder_kind") == "dspy_security_bench_reusable_workflow" else "github_attested"
    for field, expected in {
        "evidence_tier": tier, "run_url": provenance.get("run_url"),
        "source_commit": provenance.get("commit_sha"),
    }.items():
        if record[field] != expected:
            errors.append(f"{field} does not match bundle")
    if tier == "trusted_builder" and record["signer_workflow"] != TRUSTED_BUILDER_WORKFLOW:
        errors.append("unexpected trusted signer workflow")
    return tuple(errors)


def reproduction_record_errors(record) -> tuple[str, ...]:
    if not _record_shape(record, ("reproduced_by", "run_url", "created_at")):
        return ("missing, unsupported, or mistyped metadata",)
    if not _utc_timestamp(record["created_at"]) or not _https_reference(record["run_url"]):
        return ("invalid timestamp or run URL",)
    return ()
