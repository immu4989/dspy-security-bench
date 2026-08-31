"""Privacy-minimized, offline-verifiable proof of same-size log equivocation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.gossip import verify_gossip_report
from dspy_security_bench.ledger.proof import (
    validate_policy,
    verify_checkpoint_signature_bundle,
)
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AssuranceLedger ForkProof / Privacy-minimized operator misbehavior evidence"
PROTOCOL_VERSION = "assuranceledger-fork-proof-v1"
VERIFIER = "deterministic-same-size-checkpoint-conflict-verifier-v1"
CLAIM_BOUNDARY = (
    "AssuranceLedger ForkProof verifies that one policy-authorized log operator signed two "
    "different Merkle roots for the same positive tree size and that each checkpoint satisfies "
    "the disclosed witness policy. It intentionally omits log entries, reviewer registrations, "
    "review envelopes, and AssuranceQuorum reports. It does not prove which view is truthful, "
    "why the conflict occurred, witness independence, legal identity, model safety, compliance, "
    "authorization to operate, deployment authority, or risk acceptance."
)
LIMITATIONS = (
    "The artifact proves a same-size signed checkpoint conflict only; different-size forks require complete histories or a consistency-proof protocol.",
    "Source report digests are references, not proof that a recipient possesses or independently obtained the source views.",
    "Witness signatures prove key use under the embedded policy, not organizational independence or event truth.",
    "Incident response, notification, remediation, and accountable decisions remain human and organizational responsibilities.",
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOP_FIELDS = {
    "schema_version",
    "report_type",
    "protocol_version",
    "verifier",
    "source",
    "policy",
    "checkpoints",
    "finding",
    "privacy",
    "claim_boundary",
    "limitations",
    "report_sha256",
}
_SOURCE_FIELDS = {
    "gossip_report_sha256",
    "left_ledger_report_sha256",
    "right_ledger_report_sha256",
}
_CHECKPOINT_ENTRY_FIELDS = {"observer_label", "signed_checkpoint"}
_FINDING_FIELDS = {
    "status",
    "log_origin",
    "tree_size",
    "left_root_sha256",
    "right_root_sha256",
    "operator_key_sha256",
    "valid_operator_signatures",
    "valid_witness_quorums",
}
_PRIVACY_FIELDS = {
    "log_entries_embedded",
    "quorum_reports_embedded",
    "review_envelopes_embedded",
    "reviewer_key_registrations_embedded",
    "source_report_digests_disclosed",
    "automatic_actions",
}


def export_fork_proof(
    gossip_report: Mapping[str, Any], *, evidence_root: str | Path
) -> dict[str, Any]:
    """Export the first deterministic same-size fork from a valid gossip report."""
    if errors := verify_gossip_report(gossip_report, evidence_root=evidence_root):
        raise ValueError("invalid AssuranceLedger Gossip report: " + "; ".join(errors))
    selected: tuple[int, int] | None = None
    for comparison in gossip_report["comparisons"]:
        if comparison["status"] != "equivocation_evidenced":
            continue
        left_index = comparison["left_view_index"]
        right_index = comparison["right_view_index"]
        left = gossip_report["views"][left_index]["checkpoint"]["checkpoint"]
        right = gossip_report["views"][right_index]["checkpoint"]["checkpoint"]
        if left["tree_size"] == right["tree_size"] and left["root_sha256"] != right["root_sha256"]:
            selected = (left_index, right_index)
            break
    if selected is None:
        raise ValueError("gossip report contains no compactly provable same-size fork")
    left_index, right_index = selected
    left_report = gossip_report["views"][left_index]
    right_report = gossip_report["views"][right_index]
    policy = deepcopy(left_report["policy"])
    left_signed = deepcopy(left_report["checkpoint"])
    right_signed = deepcopy(right_report["checkpoint"])
    left = left_signed["checkpoint"]
    right = right_signed["checkpoint"]
    proof: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "verifier": VERIFIER,
        "source": {
            "gossip_report_sha256": gossip_report["report_sha256"],
            "left_ledger_report_sha256": left_report["report_sha256"],
            "right_ledger_report_sha256": right_report["report_sha256"],
        },
        "policy": policy,
        "checkpoints": [
            {"observer_label": f"view-{left_index}", "signed_checkpoint": left_signed},
            {"observer_label": f"view-{right_index}", "signed_checkpoint": right_signed},
        ],
        "finding": {
            "status": "operator_equivocation_proved",
            "log_origin": left["log_origin"],
            "tree_size": left["tree_size"],
            "left_root_sha256": left["root_sha256"],
            "right_root_sha256": right["root_sha256"],
            "operator_key_sha256": policy["log_operator"]["public_key_sha256"],
            "valid_operator_signatures": 2,
            "valid_witness_quorums": 2,
        },
        "privacy": {
            "log_entries_embedded": 0,
            "quorum_reports_embedded": 0,
            "review_envelopes_embedded": 0,
            "reviewer_key_registrations_embedded": 0,
            "source_report_digests_disclosed": 2,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    proof["report_sha256"] = canonical_sha256(proof)
    if errors := verify_fork_proof(proof):
        raise ValueError("generated fork proof is invalid: " + "; ".join(errors))
    return proof


def verify_fork_proof(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Verify a compact fork proof without source ledgers or network access."""
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    _exact(report, _TOP_FIELDS, "report", errors)
    if (
        report.get("schema_version") != 1
        or report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
        or report.get("verifier") != VERIFIER
    ):
        errors.append("report metadata does not match AssuranceLedger ForkProof v1")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    source = report.get("source")
    if not isinstance(source, Mapping):
        errors.append("source must be an object")
    else:
        _exact(source, _SOURCE_FIELDS, "source", errors)
        for field in _SOURCE_FIELDS:
            _digest(source.get(field), f"source.{field}", errors)
        if source.get("left_ledger_report_sha256") == source.get("right_ledger_report_sha256"):
            errors.append("source ledger report digests must be distinct")
    policy = report.get("policy")
    if not isinstance(policy, Mapping):
        errors.append("policy must be an object")
        policy = {}
    else:
        errors.extend(validate_policy(policy))
    checkpoints = report.get("checkpoints")
    signed: list[Mapping[str, Any]] = []
    if not isinstance(checkpoints, list) or len(checkpoints) != 2:
        errors.append("checkpoints must contain exactly two entries")
    else:
        labels: set[str] = set()
        for index, item in enumerate(checkpoints):
            if not isinstance(item, Mapping):
                errors.append(f"checkpoints[{index}] must be an object")
                continue
            _exact(item, _CHECKPOINT_ENTRY_FIELDS, f"checkpoints[{index}]", errors)
            label = item.get("observer_label")
            if not isinstance(label, str) or not label or len(label) > 100:
                errors.append(f"checkpoints[{index}].observer_label is invalid")
            elif label in labels:
                errors.append("checkpoint observer labels must be distinct")
            labels.add(str(label))
            value = item.get("signed_checkpoint")
            if isinstance(value, Mapping):
                signed.append(value)
                errors.extend(
                    f"checkpoints[{index}]: {message}"
                    for message in verify_checkpoint_signature_bundle(policy, value)
                )
            else:
                errors.append(f"checkpoints[{index}].signed_checkpoint must be an object")
    expected_finding: dict[str, Any] | None = None
    if len(signed) == 2:
        left = signed[0].get("checkpoint", {})
        right = signed[1].get("checkpoint", {})
        if left.get("tree_size") != right.get("tree_size"):
            errors.append("checkpoints do not have the same tree size")
        if left.get("root_sha256") == right.get("root_sha256"):
            errors.append("checkpoints do not commit to different roots")
        expected_finding = {
            "status": "operator_equivocation_proved",
            "log_origin": left.get("log_origin"),
            "tree_size": left.get("tree_size"),
            "left_root_sha256": left.get("root_sha256"),
            "right_root_sha256": right.get("root_sha256"),
            "operator_key_sha256": policy.get("log_operator", {}).get("public_key_sha256"),
            "valid_operator_signatures": 2,
            "valid_witness_quorums": 2,
        }
    finding = report.get("finding")
    if not isinstance(finding, Mapping):
        errors.append("finding must be an object")
    else:
        _exact(finding, _FINDING_FIELDS, "finding", errors)
        if expected_finding is not None and finding != expected_finding:
            errors.append("finding does not match the verified checkpoint conflict")
    privacy = report.get("privacy")
    expected_privacy = {
        "log_entries_embedded": 0,
        "quorum_reports_embedded": 0,
        "review_envelopes_embedded": 0,
        "reviewer_key_registrations_embedded": 0,
        "source_report_digests_disclosed": 2,
        "automatic_actions": 0,
    }
    if not isinstance(privacy, Mapping):
        errors.append("privacy must be an object")
    else:
        _exact(privacy, _PRIVACY_FIELDS, "privacy", errors)
        if privacy != expected_privacy:
            errors.append("privacy declaration does not match ForkProof v1")
    if report.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match ForkProof v1")
    if report.get("limitations") != list(LIMITATIONS):
        errors.append("limitations do not match ForkProof v1")
    return tuple(dict.fromkeys(errors))


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    missing = expected - set(value)
    extra = set(value) - expected
    if missing:
        errors.append(f"{label} is missing fields: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{label} has unexpected fields: {', '.join(sorted(extra))}")


def _digest(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        errors.append(f"{label} must be a lowercase SHA-256 digest")
