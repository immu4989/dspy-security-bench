"""Deterministic capability discovery for AssuranceLedger integrations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.conformance import (
    PROTOCOL_VERSION as CONFORMANCE_VERSION,
)
from dspy_security_bench.ledger.conformance import REPORT_TYPE as CONFORMANCE_REPORT
from dspy_security_bench.ledger.consistency import (
    PROTOCOL_VERSION as CONSISTENCY_VERSION,
)
from dspy_security_bench.ledger.consistency import REPORT_TYPE as CONSISTENCY_REPORT
from dspy_security_bench.ledger.gossip import PROTOCOL_VERSION as GOSSIP_VERSION
from dspy_security_bench.ledger.gossip import REPORT_TYPE as GOSSIP_REPORT
from dspy_security_bench.ledger.misbehavior import PROTOCOL_VERSION as FORK_VERSION
from dspy_security_bench.ledger.misbehavior import REPORT_TYPE as FORK_REPORT
from dspy_security_bench.ledger.observation import PROTOCOL_VERSION as OBSERVER_VERSION
from dspy_security_bench.ledger.observation import REPORT_TYPE as OBSERVER_REPORT
from dspy_security_bench.ledger.proof import PROTOCOL_VERSION as LEDGER_VERSION
from dspy_security_bench.ledger.proof import REPORT_TYPE as LEDGER_REPORT
from dspy_security_bench.ledger.rereview import PROTOCOL_VERSION as REREVIEW_VERSION
from dspy_security_bench.ledger.rereview import REPORT_TYPE as REREVIEW_REPORT
from dspy_security_bench.ledger.trust_chain import (
    PROTOCOL_VERSION as TRUST_CHAIN_VERSION,
)
from dspy_security_bench.ledger.trust_chain import REPORT_TYPE as TRUST_CHAIN_REPORT
from dspy_security_bench.ledger.trust_root import PROTOCOL_VERSION as TRUST_ROOT_VERSION
from dspy_security_bench.ledger.trust_root import REPORT_TYPE as TRUST_ROOT_REPORT
from dspy_security_bench.ledger.witness_conflict import (
    PROTOCOL_VERSION as WITNESS_CONFLICT_VERSION,
)
from dspy_security_bench.ledger.witness_conflict import (
    REPORT_TYPE as WITNESS_CONFLICT_REPORT,
)
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AssuranceLedger CapabilityManifest / Deterministic integration contract"
PROTOCOL_VERSION = "assuranceledger-capability-manifest-v1"
SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
MANIFEST_SCHEMA = "assuranceledger-capability-manifest.schema.json"
MAX_SCHEMA_BYTES = 2_000_000
SCHEMA_FILES = (
    MANIFEST_SCHEMA,
    "assuranceledger-conformance-report.schema.json",
    "assuranceledger-consistency-proof.schema.json",
    "assuranceledger-fork-proof.schema.json",
    "assuranceledger-gossip-report.schema.json",
    "assuranceledger-integration-lock-check.schema.json",
    "assuranceledger-integration-lock.schema.json",
    "assuranceledger-observer-policy.schema.json",
    "assuranceledger-observer-report.schema.json",
    "assuranceledger-policy.schema.json",
    "assuranceledger-report.schema.json",
    "assuranceledger-rereview-report.schema.json",
    "assuranceledger-trust-root-chain-report.schema.json",
    "assuranceledger-trust-root-report.schema.json",
    "assuranceledger-trust-root.schema.json",
    "assuranceledger-witness-conflict.schema.json",
)
CLAIM_BOUNDARY = (
    "CapabilityManifest binds the exact shipped AssuranceLedger JSON Schemas to the protocol "
    "versions, CLI production and verification surfaces, portability properties, disclosed "
    "data classes, and zero-action boundary declared by this implementation. It is a local "
    "integration contract, not protocol negotiation, remote-service discovery, compatibility "
    "certification, security certification, government endorsement, or deployment approval."
)
LIMITATIONS = (
    "A valid manifest proves exact agreement with the local schema directory and compiled capability table only.",
    "Schema digests bind bytes; semantically equivalent schemas with different serialization have different digests.",
    "Declared data classes are integration guidance and do not replace a deployment-specific privacy review.",
    "The manifest performs no network access, key operation, deployment, notification, revocation, or risk acceptance.",
)


def default_schema_root() -> Path:
    """Return the schema directory shipped inside the Python package."""

    return Path(__file__).resolve().parents[1] / "schemas"


def build_capability_manifest(schema_root: str | Path | None = None) -> dict[str, Any]:
    """Build a byte-bound, deterministic integration capability manifest."""

    root = default_schema_root() if schema_root is None else Path(schema_root)
    schemas = [_schema_descriptor(root, filename) for filename in SCHEMA_FILES]
    protocols = [dict(item) for item in _protocols()]
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "schema_dialect": SCHEMA_DIALECT,
        "schema_catalog": schemas,
        "protocols": protocols,
        "summary": {
            "protocol_count": len(protocols),
            "schema_count": len(schemas),
            "offline_verifier_count": sum(not item["network_required"] for item in protocols),
            "standalone_verifier_count": sum(item["standalone_verification"] for item in protocols),
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest


def verify_capability_manifest(
    manifest: Mapping[str, Any], schema_root: str | Path | None = None
) -> tuple[str, ...]:
    """Recompute a manifest from the exact local schemas and capability table."""

    if not isinstance(manifest, Mapping):
        return ("manifest must be an object",)
    errors: list[str] = []
    if (
        manifest.get("report_type") != REPORT_TYPE
        or manifest.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger CapabilityManifest")
    unsigned = dict(manifest)
    claimed = unsigned.pop("manifest_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("manifest_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("manifest is not canonical JSON data")
    try:
        expected = build_capability_manifest(schema_root)
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        errors.append(f"manifest cannot recompute: {exc}")
    else:
        if manifest != expected:
            errors.append("CapabilityManifest does not match local schemas and capabilities")
    return tuple(dict.fromkeys(errors))


def _schema_descriptor(root: Path, filename: str) -> dict[str, str]:
    path = root / filename
    if not path.is_file():
        raise ValueError(f"{filename} must be a regular file")
    if path.stat().st_size > MAX_SCHEMA_BYTES:
        raise ValueError(f"{filename} exceeds {MAX_SCHEMA_BYTES} bytes")
    raw = path.read_bytes()
    schema = json.loads(raw)
    if not isinstance(schema, dict):
        raise ValueError(f"{filename} must contain a JSON object")
    if schema.get("$schema") != SCHEMA_DIALECT:
        raise ValueError(f"{filename} must declare JSON Schema Draft 2020-12")
    schema_id = schema.get("$id")
    if not isinstance(schema_id, str) or not schema_id:
        raise ValueError(f"{filename} must declare a non-empty $id")
    return {
        "filename": filename,
        "schema_id": schema_id,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _protocols() -> tuple[dict[str, Any], ...]:
    common = {"network_required": False, "automatic_actions": 0}
    return (
        {
            **common,
            "protocol_id": LEDGER_VERSION,
            "report_type": LEDGER_REPORT,
            "artifact_schemas": [
                "assuranceledger-policy.schema.json",
                "assuranceledger-report.schema.json",
            ],
            "producer_commands": ["ledger evaluate", "ledger demo"],
            "verifier_command": "ledger verify",
            "standalone_verification": False,
            "evidence_root_required": True,
            "embedded_data_classes": [
                "reviewer identifiers",
                "review-envelope digests",
                "key lifecycle events",
                "signed checkpoints",
            ],
        },
        {
            **common,
            "protocol_id": GOSSIP_VERSION,
            "report_type": GOSSIP_REPORT,
            "artifact_schemas": ["assuranceledger-gossip-report.schema.json"],
            "producer_commands": ["ledger compare"],
            "verifier_command": "ledger verify-comparison",
            "standalone_verification": False,
            "evidence_root_required": True,
            "embedded_data_classes": [
                "source ledger reports",
                "signed checkpoints",
                "comparison findings",
            ],
        },
        {
            **common,
            "protocol_id": REREVIEW_VERSION,
            "report_type": REREVIEW_REPORT,
            "artifact_schemas": ["assuranceledger-rereview-report.schema.json"],
            "producer_commands": ["ledger plan-rereview"],
            "verifier_command": "ledger verify-rereview",
            "standalone_verification": False,
            "evidence_root_required": True,
            "embedded_data_classes": [
                "affected claim identifiers",
                "reviewer role requirements",
                "source ledger report",
            ],
        },
        {
            **common,
            "protocol_id": FORK_VERSION,
            "report_type": FORK_REPORT,
            "artifact_schemas": ["assuranceledger-fork-proof.schema.json"],
            "producer_commands": ["ledger export-fork-proof"],
            "verifier_command": "ledger verify-fork-proof",
            "standalone_verification": True,
            "evidence_root_required": False,
            "embedded_data_classes": [
                "operator and witness public keys",
                "two signed checkpoints",
                "source report digests",
            ],
        },
        {
            **common,
            "protocol_id": CONSISTENCY_VERSION,
            "report_type": CONSISTENCY_REPORT,
            "artifact_schemas": ["assuranceledger-consistency-proof.schema.json"],
            "producer_commands": ["ledger export-consistency-proof"],
            "verifier_command": "ledger verify-consistency-proof",
            "standalone_verification": True,
            "evidence_root_required": False,
            "embedded_data_classes": [
                "operator and witness public keys",
                "two signed checkpoints",
                "Merkle consistency path",
            ],
        },
        {
            **common,
            "protocol_id": OBSERVER_VERSION,
            "report_type": OBSERVER_REPORT,
            "artifact_schemas": [
                "assuranceledger-observer-policy.schema.json",
                "assuranceledger-observer-report.schema.json",
            ],
            "producer_commands": ["ledger observe", "ledger compare-receipts"],
            "verifier_command": "ledger verify-receipt-comparison",
            "standalone_verification": True,
            "evidence_root_required": False,
            "embedded_data_classes": [
                "observer identifiers",
                "declared organization identifiers",
                "hashed channel locators",
                "signed checkpoints",
            ],
        },
        {
            **common,
            "protocol_id": WITNESS_CONFLICT_VERSION,
            "report_type": WITNESS_CONFLICT_REPORT,
            "artifact_schemas": ["assuranceledger-witness-conflict.schema.json"],
            "producer_commands": ["ledger analyze-witness-conflict"],
            "verifier_command": "ledger verify-witness-conflict",
            "standalone_verification": True,
            "evidence_root_required": False,
            "embedded_data_classes": [
                "witness key identifiers",
                "declared organization identifiers",
                "compact fork proof",
            ],
        },
        {
            **common,
            "protocol_id": TRUST_ROOT_VERSION,
            "report_type": TRUST_ROOT_REPORT,
            "artifact_schemas": [
                "assuranceledger-trust-root.schema.json",
                "assuranceledger-trust-root-report.schema.json",
            ],
            "producer_commands": [
                "ledger create-trust-root",
                "ledger evaluate-trust-root",
            ],
            "verifier_command": "ledger verify-trust-root",
            "standalone_verification": True,
            "evidence_root_required": False,
            "embedded_data_classes": [
                "public trust keys and signature algorithms",
                "declared organizations and role thresholds",
                "authorized assurance-policy digests",
                "current and predecessor root signatures",
            ],
        },
        {
            **common,
            "protocol_id": TRUST_CHAIN_VERSION,
            "report_type": TRUST_CHAIN_REPORT,
            "artifact_schemas": [
                "assuranceledger-trust-root.schema.json",
                "assuranceledger-trust-root-chain-report.schema.json",
            ],
            "producer_commands": ["ledger evaluate-trust-chain"],
            "verifier_command": "ledger verify-trust-chain",
            "standalone_verification": True,
            "evidence_root_required": False,
            "embedded_data_classes": [
                "ordered trust-root history",
                "per-hop threshold verification outcomes",
                "algorithm transitions and root validity windows",
                "authorized assurance-policy digests",
            ],
        },
        {
            **common,
            "protocol_id": CONFORMANCE_VERSION,
            "report_type": CONFORMANCE_REPORT,
            "artifact_schemas": ["assuranceledger-conformance-report.schema.json"],
            "producer_commands": ["ledger conformance"],
            "verifier_command": "ledger verify-conformance",
            "standalone_verification": False,
            "evidence_root_required": True,
            "embedded_data_classes": [
                "source artifact digests",
                "mutation digests",
                "verifier error strings",
            ],
        },
        {
            **common,
            "protocol_id": "assuranceledger-integration-lock-v1",
            "report_type": "AssuranceLedger IntegrationLock / Owner-pinned capability baseline",
            "artifact_schemas": [
                "assuranceledger-integration-lock.schema.json",
                "assuranceledger-integration-lock-check.schema.json",
            ],
            "producer_commands": [
                "ledger lock-capabilities",
                "ledger check-capability-lock",
            ],
            "verifier_command": "ledger verify-capability-lock",
            "standalone_verification": False,
            "evidence_root_required": False,
            "embedded_data_classes": [
                "owner-pinned schema digests",
                "owner-pinned protocol contracts",
                "candidate manifest digest",
                "compatibility findings",
            ],
        },
    )
