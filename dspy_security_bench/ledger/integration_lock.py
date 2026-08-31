"""Owner-pinned compatibility locks for AssuranceLedger partner integrations."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.capabilities import verify_capability_manifest
from dspy_security_bench.mission.loader import canonical_sha256

LOCK_REPORT_TYPE = "AssuranceLedger IntegrationLock / Owner-pinned capability baseline"
LOCK_PROTOCOL_VERSION = "assuranceledger-integration-lock-v1"
CHECK_REPORT_TYPE = "AssuranceLedger IntegrationLockCheck / Capability drift evidence"
CHECK_PROTOCOL_VERSION = "assuranceledger-integration-lock-check-v1"
PINNED_FIELDS = (
    "report_type",
    "artifact_schemas",
    "verifier_command",
    "standalone_verification",
    "evidence_root_required",
    "network_required",
    "automatic_actions",
    "embedded_data_classes",
)
LOCK_FIELDS = {
    "schema_version",
    "report_type",
    "protocol_version",
    "source_manifest_sha256",
    "required_schemas",
    "required_protocols",
    "summary",
    "claim_boundary",
    "limitations",
    "lock_sha256",
}
PROTOCOL_FIELDS = {"protocol_id", *PINNED_FIELDS, "artifact_schema_sha256"}
CLAIM_BOUNDARY = (
    "IntegrationLock records an owner-reviewed AssuranceLedger capability baseline and checks "
    "a locally verified candidate against every pinned protocol, schema digest, verification "
    "boundary, and disclosed data class. Requirements-satisfied means the candidate preserves "
    "those exact pins; it is not interoperability certification, vulnerability analysis, "
    "government endorsement, deployment approval, or proof that the owner reviewed the lock."
)
LIMITATIONS = (
    "The lock is unsigned; owners must protect and review it through their own source-control or artifact-governance process.",
    "Additional candidate protocols and schemas are allowed because the lock is a minimum exact baseline.",
    "A satisfied lock says nothing about behavior beyond the pinned manifest fields and local schema bytes.",
    "The checker performs no network access, upgrade, rollback, deployment, notification, or risk acceptance.",
)


def build_integration_lock(
    manifest: Mapping[str, Any], schema_root: str | Path | None = None
) -> dict[str, Any]:
    """Create a deterministic lock from a locally recomputable capability manifest."""

    if errors := verify_capability_manifest(manifest, schema_root):
        raise ValueError("capability manifest is not locally verified: " + "; ".join(errors))
    schema_digests = {item["filename"]: item["sha256"] for item in manifest["schema_catalog"]}
    protocols = [_pinned_protocol(item, schema_digests) for item in manifest["protocols"]]
    lock: dict[str, Any] = {
        "schema_version": 1,
        "report_type": LOCK_REPORT_TYPE,
        "protocol_version": LOCK_PROTOCOL_VERSION,
        "source_manifest_sha256": manifest["manifest_sha256"],
        "required_schemas": dict(sorted(schema_digests.items())),
        "required_protocols": protocols,
        "summary": {
            "required_schema_count": len(schema_digests),
            "required_protocol_count": len(protocols),
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    lock["lock_sha256"] = canonical_sha256(lock)
    return lock


def check_integration_lock(
    lock: Mapping[str, Any],
    candidate_manifest: Mapping[str, Any],
    schema_root: str | Path | None = None,
) -> dict[str, Any]:
    """Compare a verified candidate to every exact requirement in an owner lock."""

    lock_errors = _verify_lock_integrity(lock)
    manifest_errors = verify_capability_manifest(candidate_manifest, schema_root)
    findings: list[dict[str, str]] = []
    for error in lock_errors:
        findings.append(_finding("invalid-lock", "integration-lock", error))
    for error in manifest_errors:
        findings.append(_finding("invalid-candidate", "capability-manifest", error))
    if not lock_errors and not manifest_errors:
        findings.extend(_compare_requirements(lock, candidate_manifest))
    status = "requirements_satisfied" if not findings else "capability_drift"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": CHECK_REPORT_TYPE,
        "protocol_version": CHECK_PROTOCOL_VERSION,
        "lock_sha256": _bound_digest(lock, "lock_sha256"),
        "candidate_manifest_sha256": _bound_digest(candidate_manifest, "manifest_sha256"),
        "findings": findings,
        "summary": {
            "status": status,
            "finding_count": len(findings),
            "required_schema_count": _collection_length(lock.get("required_schemas")),
            "required_protocol_count": _collection_length(lock.get("required_protocols")),
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_integration_lock_check(
    report: Mapping[str, Any],
    lock: Mapping[str, Any],
    candidate_manifest: Mapping[str, Any],
    schema_root: str | Path | None = None,
) -> tuple[str, ...]:
    """Recompute a saved compatibility check from its lock and candidate."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != CHECK_REPORT_TYPE
        or report.get("protocol_version") != CHECK_PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger IntegrationLockCheck")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = check_integration_lock(lock, candidate_manifest, schema_root)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"IntegrationLockCheck cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("IntegrationLockCheck does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _verify_lock_integrity(lock: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(lock, Mapping):
        return ("lock must be an object",)
    errors: list[str] = []
    if (
        lock.get("report_type") != LOCK_REPORT_TYPE
        or lock.get("protocol_version") != LOCK_PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger IntegrationLock")
    if set(lock) != LOCK_FIELDS:
        errors.append("IntegrationLock fields are not exact")
    unsigned = dict(lock)
    claimed = unsigned.pop("lock_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("lock_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("lock is not canonical JSON data")
    if not _is_digest(lock.get("source_manifest_sha256")):
        errors.append("source_manifest_sha256 must be a lowercase SHA-256 digest")
    schemas = lock.get("required_schemas")
    if not isinstance(schemas, Mapping) or not schemas:
        errors.append("required_schemas must be a non-empty object")
        schemas = {}
    else:
        for filename, digest in schemas.items():
            if not isinstance(filename, str) or not filename.startswith("assuranceledger-"):
                errors.append("required_schemas contains an invalid filename")
            if not _is_digest(digest):
                errors.append(f"required schema {filename} has an invalid digest")
    protocols = lock.get("required_protocols")
    if not isinstance(protocols, list) or not protocols:
        errors.append("required_protocols must be a non-empty array")
        protocols = []
    seen_protocols: set[str] = set()
    for index, protocol in enumerate(protocols):
        if not isinstance(protocol, Mapping) or set(protocol) != PROTOCOL_FIELDS:
            errors.append(f"required_protocols[{index}] fields are not exact")
            continue
        protocol_id = protocol.get("protocol_id")
        if not isinstance(protocol_id, str) or not protocol_id:
            errors.append(f"required_protocols[{index}] has an invalid protocol_id")
        elif protocol_id in seen_protocols:
            errors.append(f"required protocol {protocol_id} is duplicated")
        else:
            seen_protocols.add(protocol_id)
        artifact_schemas = protocol.get("artifact_schemas")
        artifact_digests = protocol.get("artifact_schema_sha256")
        if (
            not isinstance(artifact_schemas, list)
            or not artifact_schemas
            or not all(isinstance(item, str) and item for item in artifact_schemas)
            or len(artifact_schemas) != len(set(artifact_schemas))
        ):
            errors.append(f"required protocol {protocol_id} has invalid artifact_schemas")
            artifact_schemas = []
        if not isinstance(artifact_digests, Mapping) or set(artifact_digests) != set(
            artifact_schemas
        ):
            errors.append(f"required protocol {protocol_id} schema digest keys do not match")
            artifact_digests = {}
        for filename, digest in artifact_digests.items():
            if not _is_digest(digest) or schemas.get(filename) != digest:
                errors.append(
                    f"required protocol {protocol_id} schema digest is not pinned consistently"
                )
        if not isinstance(protocol.get("report_type"), str) or not protocol.get("report_type"):
            errors.append(f"required protocol {protocol_id} has an invalid report_type")
        if not isinstance(protocol.get("verifier_command"), str) or not protocol.get(
            "verifier_command", ""
        ).startswith("ledger verify"):
            errors.append(f"required protocol {protocol_id} has an invalid verifier_command")
        for field in (
            "standalone_verification",
            "evidence_root_required",
            "network_required",
        ):
            if not isinstance(protocol.get(field), bool):
                errors.append(f"required protocol {protocol_id} has an invalid {field}")
        if (
            not isinstance(protocol.get("automatic_actions"), int)
            or isinstance(protocol.get("automatic_actions"), bool)
            or protocol.get("automatic_actions") < 0
        ):
            errors.append(f"required protocol {protocol_id} has invalid automatic_actions")
        data_classes = protocol.get("embedded_data_classes")
        if (
            not isinstance(data_classes, list)
            or not data_classes
            or not all(isinstance(item, str) and item for item in data_classes)
            or len(data_classes) != len(set(data_classes))
        ):
            errors.append(f"required protocol {protocol_id} has invalid embedded_data_classes")
    summary = lock.get("summary")
    expected_summary = {
        "required_schema_count": len(schemas),
        "required_protocol_count": len(protocols),
        "automatic_actions": 0,
    }
    if summary != expected_summary:
        errors.append("IntegrationLock summary does not recompute")
    if lock.get("claim_boundary") != CLAIM_BOUNDARY or lock.get("limitations") != list(LIMITATIONS):
        errors.append("IntegrationLock claim boundary or limitations changed")
    return tuple(dict.fromkeys(errors))


def _pinned_protocol(
    protocol: Mapping[str, Any], schema_digests: Mapping[str, str]
) -> dict[str, Any]:
    pinned = {"protocol_id": protocol["protocol_id"]}
    pinned.update({field: protocol[field] for field in PINNED_FIELDS})
    pinned["artifact_schema_sha256"] = {
        filename: schema_digests[filename] for filename in protocol["artifact_schemas"]
    }
    return pinned


def _compare_requirements(
    lock: Mapping[str, Any], candidate: Mapping[str, Any]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    candidate_schemas = {item["filename"]: item["sha256"] for item in candidate["schema_catalog"]}
    for filename, expected in lock["required_schemas"].items():
        observed = candidate_schemas.get(filename)
        if observed != expected:
            findings.append(
                _finding(
                    "schema-drift",
                    filename,
                    f"expected sha256 {expected}; observed {observed or 'missing'}",
                )
            )
    candidates = {item["protocol_id"]: item for item in candidate["protocols"]}
    for required in lock["required_protocols"]:
        protocol_id = required["protocol_id"]
        observed = candidates.get(protocol_id)
        if observed is None:
            findings.append(_finding("missing-protocol", protocol_id, "required protocol missing"))
            continue
        observed_pin = _pinned_protocol(observed, candidate_schemas)
        for field in (*PINNED_FIELDS, "artifact_schema_sha256"):
            if observed_pin[field] != required[field]:
                findings.append(
                    _finding(
                        "protocol-contract-drift",
                        f"{protocol_id}:{field}",
                        "candidate value differs from the owner-pinned baseline",
                    )
                )
    return findings


def _finding(rule_id: str, subject: str, detail: str) -> dict[str, str]:
    return {"rule_id": rule_id, "subject": subject, "detail": detail}


def _bound_digest(payload: Mapping[str, Any], field: str) -> str:
    claimed = payload.get(field)
    if _is_digest(claimed):
        return claimed
    return canonical_sha256(payload)


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _collection_length(value: Any) -> int:
    return len(value) if isinstance(value, (Mapping, list)) else 0
