"""Attribute witness double-signing within a verified same-size fork proof."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from dspy_security_bench.ledger.misbehavior import verify_fork_proof
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AssuranceLedger WitnessConflict / Fork cosignature attribution"
PROTOCOL_VERSION = "assuranceledger-witness-conflict-v1"
ANALYZER = "deterministic-fork-cosignature-intersection-v1"
CLAIM_BOUNDARY = (
    "AssuranceLedger WitnessConflict natively verifies a compact same-size ForkProof and "
    "identifies policy-authorized witness keys that signed both conflicting checkpoints. A "
    "shared key signature is cryptographic evidence that the key was used on both views; it "
    "does not prove who controlled the key, organizational intent, compromise cause, legal "
    "liability, model safety, compliance, authorization to operate, deployment authority, or "
    "risk acceptance."
)
LIMITATIONS = (
    "Attribution is to policy key identifiers and declared organizations, not externally proofed people or legal entities.",
    "A witness appearing on only one side is not thereby proven honest, independent, or uncompromised.",
    "The analyzer does not infer motive or distinguish compromise, implementation failure, operator collusion, or key misuse.",
    "No notification, key revocation, remediation, deployment, or authorization action is taken.",
)


def analyze_witness_conflict(fork_proof: Mapping[str, Any]) -> dict[str, Any]:
    if errors := verify_fork_proof(fork_proof):
        raise ValueError("invalid AssuranceLedger ForkProof: " + "; ".join(errors))
    policy = fork_proof["policy"]
    witness_map = {item["entity_id"]: item for item in policy["witnesses"]}
    left = {
        (item["signer_id"], item["keyid"])
        for item in fork_proof["checkpoints"][0]["signed_checkpoint"]["witness_signatures"]
    }
    right = {
        (item["signer_id"], item["keyid"])
        for item in fork_proof["checkpoints"][1]["signed_checkpoint"]["witness_signatures"]
    }
    shared = sorted(left & right)
    witness_results = []
    for signer_id, keyid in sorted(left | right):
        descriptor = witness_map[signer_id]
        on_left = (signer_id, keyid) in left
        on_right = (signer_id, keyid) in right
        witness_results.append(
            {
                "witness_id": signer_id,
                "organization_id": descriptor["organization_id"],
                "public_key_sha256": keyid,
                "signed_left_checkpoint": on_left,
                "signed_right_checkpoint": on_right,
                "status": "signed_both_conflicting_checkpoints"
                if on_left and on_right
                else "signed_one_conflicting_checkpoint",
            }
        )
    shared_organizations = {witness_map[signer_id]["organization_id"] for signer_id, _ in shared}
    status = (
        "operator_and_witness_conflict_evidenced"
        if shared
        else "operator_conflict_without_shared_witness"
    )
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "fork_proof": deepcopy(dict(fork_proof)),
        "witness_results": witness_results,
        "summary": {
            "status": status,
            "witnesses_on_left": len(left),
            "witnesses_on_right": len(right),
            "shared_witness_keys": len(shared),
            "shared_witness_organizations": len(shared_organizations),
            "automatic_notifications": 0,
            "automatic_revocations": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_witness_conflict_report(report: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger WitnessConflict report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = analyze_witness_conflict(report.get("fork_proof", {}))
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("WitnessConflict report does not recompute exactly")
    return tuple(dict.fromkeys(errors))
