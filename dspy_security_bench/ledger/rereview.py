"""Minimal claim re-review planning after reviewer trust changes."""

from __future__ import annotations

import base64
import json
from collections import defaultdict
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.proof import verify_ledger_report
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AssuranceLedger ReReview / Minimal claim re-review plan"
PROTOCOL_VERSION = "assuranceledger-rereview-v1"
ANALYZER = "deterministic-minimal-claim-rereview-planner-v1"
HISTORICAL_POLICIES = ("require-current-key", "allow-until-review-expiry")
CLAIM_BOUNDARY = (
    "AssuranceLedger ReReview natively verifies one AssuranceLedger report and computes the "
    "smallest declared claim/role set whose prior review is invalidated, incomplete, or no "
    "longer current under the owner-selected historical-key policy. It does not select a "
    "replacement person, resolve an evidence gap, revoke or approve a deployment, determine "
    "compliance, authorize operation, accept risk, or prove that the source observations are true."
)
LIMITATIONS = (
    "Minimality is relative to the frozen AssuranceQuorum claim assignments and supplied ledger evidence.",
    "A re-review request does not establish that underlying technical evidence remains sufficient or complete.",
    "Allowing a retired key until review expiry is an owner policy choice, not a recommendation from this tool.",
    "Evidence-gap statements remain unresolved; a replacement favorable signature cannot erase them.",
)


def plan_rereview(
    ledger_report: Mapping[str, Any],
    *,
    evidence_root: str | Path,
    historical_policy: str = "require-current-key",
) -> dict[str, Any]:
    if historical_policy not in HISTORICAL_POLICIES:
        raise ValueError(f"unsupported historical review policy {historical_policy!r}")
    source_errors = list(verify_ledger_report(ledger_report, evidence_root=evidence_root))
    quorum_report = ledger_report.get("quorum_report", {})
    trust_by_envelope = {
        item.get("envelope_sha256"): item
        for item in ledger_report.get("review_results", [])
        if isinstance(item, Mapping)
    }
    review_records = []
    for envelope in quorum_report.get("review_envelopes", []):
        digest = _safe_digest(envelope)
        predicate = _predicate(envelope)
        reviewer = predicate.get("reviewer", {})
        trust = trust_by_envelope.get(digest, {})
        review_records.append(
            {
                "envelope_sha256": digest,
                "signer_id": reviewer.get("signer_id"),
                "role": reviewer.get("role"),
                "decision": predicate.get("decision"),
                "claim_ids": list(predicate.get("claim_ids", [])),
                "review_expires_at": predicate.get("expires_at"),
                "trust_status": trust.get("status", "trust_evidence_incomplete"),
            }
        )
    claim_results = []
    request_groups: dict[tuple[str, str, str | None], set[str]] = defaultdict(set)
    if not source_errors:
        for requirement in quorum_report.get("policy", {}).get("claim_requirements", []):
            claim_id = requirement["claim_id"]
            related = [item for item in review_records if claim_id in item["claim_ids"]]
            current_roles = _roles(related, "reviewer_trust_current", "evidence-sufficient")
            historical_roles = _roles(related, "reviewer_trust_historical", "evidence-sufficient")
            invalidated_roles = _roles(related, "reviewer_trust_invalidated", "evidence-sufficient")
            incomplete_roles = _roles(related, "trust_evidence_incomplete", "evidence-sufficient")
            gap_roles = sorted(
                {
                    str(item["role"])
                    for item in related
                    if item["decision"] == "evidence-gap"
                    and item["trust_status"]
                    in {"reviewer_trust_current", "reviewer_trust_historical"}
                }
            )
            accepted = set(current_roles)
            if historical_policy == "allow-until-review-expiry":
                accepted.update(historical_roles)
            missing_roles = sorted(set(requirement["required_roles"]) - accepted)
            if gap_roles:
                status = "unresolved_evidence_gap"
            elif missing_roles:
                status = "rereview_required"
            elif historical_roles:
                status = "renewal_due"
            else:
                status = "review_current"
            claim_results.append(
                {
                    "claim_id": claim_id,
                    "status": status,
                    "required_roles": list(requirement["required_roles"]),
                    "current_roles": current_roles,
                    "historical_roles": historical_roles,
                    "invalidated_roles": invalidated_roles,
                    "incomplete_roles": incomplete_roles,
                    "gap_roles": gap_roles,
                    "missing_roles": missing_roles,
                }
            )
            for item in related:
                role = str(item["role"])
                reason = _request_reason(item["trust_status"], historical_policy)
                if role in missing_roles and reason is not None:
                    request_groups[(role, reason, item["signer_id"])].add(claim_id)
            observed_roles = {str(item["role"]) for item in related}
            for role in set(missing_roles) - observed_roles:
                request_groups[(role, "missing-required-role", None)].add(claim_id)
    requests = [
        {
            "role": role,
            "reason": reason,
            "prior_signer_id": signer_id,
            "claim_ids": sorted(claim_ids),
            "replacement_selected": False,
        }
        for (role, reason, signer_id), claim_ids in sorted(request_groups.items())
    ]
    counts = {
        status: sum(item["status"] == status for item in claim_results)
        for status in (
            "review_current",
            "renewal_due",
            "rereview_required",
            "unresolved_evidence_gap",
        )
    }
    if source_errors:
        status = "invalid_source_evidence"
    elif counts["unresolved_evidence_gap"]:
        status = "evidence_gap_unresolved"
    elif counts["rereview_required"]:
        status = "rereview_required"
    elif counts["renewal_due"]:
        status = "renewal_due"
    else:
        status = "no_rereview_indicated"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "historical_policy": historical_policy,
        "ledger_report": deepcopy(dict(ledger_report)),
        "source_errors": source_errors,
        "review_records": review_records,
        "claim_results": claim_results,
        "rereview_requests": requests,
        "summary": {
            "status": status,
            "claim_count": len(claim_results),
            "claim_status_counts": counts,
            "rereview_request_count": len(requests),
            "claims_requiring_rereview": sum(
                item["status"] == "rereview_required" for item in claim_results
            ),
            "replacement_reviewers_selected": 0,
            "automatic_deployment_actions": 0,
            "automatic_risk_acceptances": 0,
            "automatic_authorizations_to_operate": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_rereview_report(
    report: Mapping[str, Any], *, evidence_root: str | Path
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger ReReview report type or protocol version")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = plan_rereview(
            report.get("ledger_report", {}),
            evidence_root=evidence_root,
            historical_policy=report.get("historical_policy"),
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("AssuranceLedger ReReview report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _predicate(envelope: Any) -> Mapping[str, Any]:
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(payload)
        predicate = statement["predicate"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return {}
    return predicate if isinstance(predicate, Mapping) else {}


def _roles(records: list[dict[str, Any]], trust: str, decision: str) -> list[str]:
    return sorted(
        {
            str(item["role"])
            for item in records
            if item["trust_status"] == trust and item["decision"] == decision
        }
    )


def _request_reason(trust_status: str, historical_policy: str) -> str | None:
    if trust_status == "reviewer_trust_invalidated":
        return "compromise-invalidated"
    if trust_status == "trust_evidence_incomplete":
        return "trust-evidence-incomplete"
    if trust_status == "reviewer_trust_historical" and historical_policy == "require-current-key":
        return "key-retired"
    return None


def _safe_digest(payload: Any) -> str:
    try:
        return canonical_sha256(payload)
    except (TypeError, ValueError):
        return "unavailable"
