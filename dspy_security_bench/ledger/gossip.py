"""Offline checkpoint gossip and split-view evidence for AssuranceLedger."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.proof import verify_ledger_report
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AssuranceLedger Gossip / Cross-view consistency evidence"
PROTOCOL_VERSION = "assuranceledger-gossip-v1"
ANALYZER = "deterministic-cross-view-prefix-analyzer-v1"
MAX_VIEWS = 50
CLAIM_BOUNDARY = (
    "AssuranceLedger Gossip natively recomputes supplied AssuranceLedger reports and compares "
    "their operator-signed checkpoint roots and complete event prefixes. Conflicting valid "
    "checkpoints from one origin and policy evidence equivocation within the supplied views. "
    "A consistent result applies only to the views supplied; it does not prove global log "
    "consistency, observer independence, complete dissemination, identity, model safety, "
    "compliance, deployment authority, authorization to operate, or risk acceptance."
)
LIMITATIONS = (
    "Consistency is bounded to supplied, natively verified views; an undisclosed fork remains undiscovered.",
    "The protocol compares complete embedded event prefixes rather than a compact RFC 6962 consistency-proof wire format.",
    "File provenance and independent delivery channels are deployment responsibilities unless separately attested.",
    "Conflicting operator-signed checkpoints evidence log behavior, not the truth of any logged lifecycle event.",
)


def compare_views(
    reports: Sequence[Mapping[str, Any]], *, evidence_root: str | Path
) -> dict[str, Any]:
    if not isinstance(reports, list) or not 2 <= len(reports) <= MAX_VIEWS:
        raise ValueError(f"reports must contain 2 to {MAX_VIEWS} AssuranceLedger views")
    view_results = []
    valid_views: list[tuple[int, Mapping[str, Any]]] = []
    for index, report in enumerate(reports):
        errors = list(verify_ledger_report(report, evidence_root=evidence_root))
        checkpoint = report.get("checkpoint", {}).get("checkpoint", {})
        view_results.append(
            {
                "view_index": index,
                "report_sha256": report.get("report_sha256"),
                "status": "valid" if not errors else "invalid",
                "log_origin": checkpoint.get("log_origin"),
                "policy_sha256": checkpoint.get("policy_sha256"),
                "tree_size": checkpoint.get("tree_size"),
                "root_sha256": checkpoint.get("root_sha256"),
                "checkpoint_sha256": _safe_digest(report.get("checkpoint")),
                "errors": errors,
            }
        )
        if not errors:
            valid_views.append((index, report))
    comparisons = []
    fork_count = 0
    for position, (left_index, left) in enumerate(valid_views):
        for right_index, right in valid_views[position + 1 :]:
            comparison = _compare_pair(left_index, left, right_index, right)
            comparisons.append(comparison)
            fork_count += comparison["status"] == "equivocation_evidenced"
    invalid_count = sum(item["status"] == "invalid" for item in view_results)
    identities = {
        (item["log_origin"], item["policy_sha256"])
        for item in view_results
        if item["status"] == "valid"
    }
    distinct_checkpoints = {
        item["checkpoint_sha256"] for item in view_results if item["status"] == "valid"
    }
    if invalid_count or len(identities) > 1:
        status = "invalid_view_evidence"
    elif fork_count:
        status = "equivocation_evidenced"
    elif len(distinct_checkpoints) < 2:
        status = "insufficient_view_diversity"
    else:
        status = "views_consistent"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "views": deepcopy(list(reports)),
        "view_results": view_results,
        "comparisons": comparisons,
        "summary": {
            "status": status,
            "submitted_views": len(reports),
            "valid_views": len(valid_views),
            "invalid_views": invalid_count,
            "distinct_checkpoints": len(distinct_checkpoints),
            "pair_comparisons": len(comparisons),
            "equivocation_pairs": fork_count,
            "automatic_deployment_actions": 0,
            "automatic_risk_acceptances": 0,
            "automatic_authorizations_to_operate": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_gossip_report(
    report: Mapping[str, Any], *, evidence_root: str | Path
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger Gossip report type or protocol version")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = compare_views(report.get("views", []), evidence_root=evidence_root)
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("AssuranceLedger Gossip report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _compare_pair(
    left_index: int,
    left: Mapping[str, Any],
    right_index: int,
    right: Mapping[str, Any],
) -> dict[str, Any]:
    left_checkpoint = left["checkpoint"]["checkpoint"]
    right_checkpoint = right["checkpoint"]["checkpoint"]
    same_identity = (
        left_checkpoint["log_origin"] == right_checkpoint["log_origin"]
        and left_checkpoint["policy_sha256"] == right_checkpoint["policy_sha256"]
    )
    smaller_index, smaller, larger_index, larger = (
        (left_index, left, right_index, right)
        if left_checkpoint["tree_size"] <= right_checkpoint["tree_size"]
        else (right_index, right, left_index, left)
    )
    smaller_checkpoint = smaller["checkpoint"]["checkpoint"]
    larger_checkpoint = larger["checkpoint"]["checkpoint"]
    size = smaller_checkpoint["tree_size"]
    prefix_matches = smaller["entries"] == larger["entries"][:size]
    root_matches = smaller_checkpoint["root_sha256"] == _prefix_root(larger, size)
    if not same_identity:
        status = "incomparable_identity"
        reason = "views name different log origins or policies"
    elif prefix_matches and root_matches:
        status = "consistent_prefix"
        reason = "the smaller complete event history is an exact prefix of the larger view"
    else:
        status = "equivocation_evidenced"
        reason = (
            "operator-signed checkpoints at the same tree size have different roots"
            if smaller_checkpoint["tree_size"] == larger_checkpoint["tree_size"]
            else "the smaller operator-signed history is not a prefix of the larger view"
        )
    return {
        "left_view_index": left_index,
        "right_view_index": right_index,
        "smaller_view_index": smaller_index,
        "larger_view_index": larger_index,
        "status": status,
        "same_log_identity": same_identity,
        "prefix_matches": prefix_matches,
        "prefix_root_matches": root_matches,
        "reason": reason,
    }


def _prefix_root(report: Mapping[str, Any], size: int) -> str:
    from dspy_security_bench.ledger.proof import merkle_root

    return merkle_root(report["entries"][:size])


def _safe_digest(payload: Any) -> str:
    try:
        return canonical_sha256(payload)
    except (TypeError, ValueError):
        return "unavailable"
