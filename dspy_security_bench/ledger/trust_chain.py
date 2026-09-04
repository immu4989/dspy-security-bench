"""Bounded multi-hop trust-root catch-up for stale AssuranceLedger clients."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

from dspy_security_bench.ledger.trust_root import (
    SIGNATURE_SCHEMES,
    evaluate_trust_root,
    validate_trust_root,
)
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AssuranceLedger TrustRootChain / Multi-hop trust-anchor continuity evidence"
PROTOCOL_VERSION = "assuranceledger-trust-root-chain-v1"
ANALYZER = "deterministic-multihop-trust-root-analyzer-v1"
MAX_CHAIN_ROOTS = 64
TRUSTED_CHAIN_STATUSES = ("trusted_chain",)
CLAIM_BOUNDARY = (
    "AssuranceTrustRootChain verifies an ordered, bounded sequence of exact trust-root "
    "successors from a caller-selected root object or independently pinned root digest. "
    "Every hop must advance by one version, bind its predecessor digest, and satisfy both "
    "predecessor and candidate root thresholds. Historical intermediate expiration is "
    "recorded but does not break catch-up; the final root must be currently valid and must "
    "authorize every supplied policy digest. A trusted result establishes only continuity "
    "across the supplied chain."
)
LIMITATIONS = (
    "The verifier cannot discover a withheld newer root; callers should set minimum_final_version from an independent channel when freshness matters.",
    "Expired intermediates are accepted only as historical links; an expired or future-issued final root is never trusted.",
    "The chain is limited to 64 supplied roots to bound local verification work and embedded report size.",
    "This format is inspired by TUF root catch-up but is not TUF-compatible and does not implement repository download behavior.",
    "A valid chain does not prove legal identity, organizational independence, private-key custody, policy quality, compliance, authorization to operate, or deployment approval.",
    "The verifier performs no network access, root retrieval, key generation, deployment, notification, revocation, or automatic action.",
)


def evaluate_trust_root_chain(
    roots: Sequence[Mapping[str, Any]],
    *,
    evaluation_time: int,
    trusted_root: Mapping[str, Any] | None = None,
    expected_root_sha256: str | None = None,
    expected_trust_domain: str | None = None,
    minimum_final_version: int | None = None,
    policies: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Verify a pinned bootstrap and zero or more exact root rotations offline.

    When ``trusted_root`` is supplied, every item in ``roots`` is a successor. When a
    pinned digest is used, ``roots[0]`` is the pinned root and later items are successors.
    """

    if trusted_root is not None and expected_root_sha256 is not None:
        raise ValueError("select either a trusted root or a pinned root digest, not both")
    if isinstance(evaluation_time, bool) or not isinstance(evaluation_time, int):
        raise ValueError("evaluation_time must be an integer Unix timestamp")
    if not isinstance(roots, Sequence) or isinstance(roots, (str, bytes)) or not roots:
        raise ValueError("roots must contain at least one trust root")
    if len(roots) > MAX_CHAIN_ROOTS:
        raise ValueError(f"roots exceeds the {MAX_CHAIN_ROOTS}-root verification limit")
    if minimum_final_version is not None and (
        isinstance(minimum_final_version, bool)
        or not isinstance(minimum_final_version, int)
        or minimum_final_version < 1
    ):
        raise ValueError("minimum_final_version must be a positive integer")
    if expected_trust_domain is not None and (
        not isinstance(expected_trust_domain, str) or not expected_trust_domain.strip()
    ):
        raise ValueError("expected_trust_domain must be a non-empty string")

    root_inputs = [deepcopy(dict(item)) for item in roots]
    final_root = root_inputs[-1]
    anchor_root = deepcopy(dict(trusted_root)) if trusted_root is not None else root_inputs[0]
    anchor_mode = (
        "trusted-root"
        if trusted_root is not None
        else "pinned-root-digest"
        if expected_root_sha256 is not None
        else "none"
    )
    anchor_errors: list[str] = []
    chain_errors: list[str] = []
    anchor_source_errors = list(validate_trust_root(anchor_root))

    if expected_root_sha256 is not None:
        pinned = evaluate_trust_root(
            anchor_root,
            evaluation_time=_historical_evaluation_time(anchor_root, evaluation_time),
            expected_root_sha256=expected_root_sha256,
            expected_trust_domain=expected_trust_domain,
        )
        anchor_errors.extend(pinned["trust_errors"])
    elif trusted_root is None:
        anchor_errors.append(
            "no trusted root or independently pinned bootstrap digest was supplied"
        )
    if expected_trust_domain is not None and (
        anchor_root.get("trust_domain") != expected_trust_domain
    ):
        message = "anchor trust_domain does not match the expected domain"
        if message not in anchor_errors:
            anchor_errors.append(message)

    root_results: list[dict[str, Any]] = []
    for index, root in enumerate(root_inputs):
        issued_at = _plain_int(root.get("issued_at"))
        expires_at = _plain_int(root.get("expires_at"))
        root_results.append(
            {
                "root_index": index,
                "version": _plain_int(root.get("version")),
                "root_sha256": _digest_or_none(root.get("root_sha256")),
                "source_errors": list(validate_trust_root(root)),
                "expired_at_evaluation": (expires_at is not None and evaluation_time >= expires_at),
                "not_yet_valid_at_evaluation": (
                    issued_at is not None and evaluation_time < issued_at
                ),
            }
        )

    transitions: list[dict[str, Any]] = []
    previous = anchor_root
    successor_start = 0 if trusted_root is not None else 1
    for root_index in range(successor_start, len(root_inputs)):
        candidate = root_inputs[root_index]
        transition_report = evaluate_trust_root(
            candidate,
            evaluation_time=_historical_evaluation_time(candidate, evaluation_time),
            trusted_root=previous,
            expected_trust_domain=expected_trust_domain,
        )
        transition_errors = list(transition_report["trust_errors"])
        previous_issued = _plain_int(previous.get("issued_at"))
        candidate_issued = _plain_int(candidate.get("issued_at"))
        transition_status = transition_report["summary"]["status"]
        if (
            previous_issued is not None
            and candidate_issued is not None
            and candidate_issued < previous_issued
        ):
            transition_errors.append("candidate issued_at precedes its immediate predecessor")
            if transition_status == "trusted_rotation":
                transition_status = "trust_discontinuity"
        transitions.append(
            {
                "transition_index": len(transitions),
                "from_version": transition_report["summary"]["previous_version"],
                "to_version": transition_report["summary"]["candidate_version"],
                "from_root_sha256": _digest_or_none(previous.get("root_sha256")),
                "to_root_sha256": _digest_or_none(candidate.get("root_sha256")),
                "status": transition_status,
                "source_errors": transition_report["source_errors"],
                "trust_errors": transition_errors,
                "current_valid_root_signatures": transition_report["summary"][
                    "current_valid_root_signatures"
                ],
                "current_distinct_root_organizations": transition_report["summary"][
                    "current_distinct_root_organizations"
                ],
                "previous_valid_root_signatures": transition_report["summary"][
                    "previous_valid_root_signatures"
                ],
                "previous_distinct_root_organizations": transition_report["summary"][
                    "previous_distinct_root_organizations"
                ],
                "algorithm_transition": transition_report["algorithm_transition"],
            }
        )
        previous = candidate

    final_evaluation = evaluate_trust_root(
        final_root,
        evaluation_time=evaluation_time,
        expected_root_sha256=_digest_or_none(final_root.get("root_sha256")),
        expected_trust_domain=expected_trust_domain,
        minimum_version=minimum_final_version,
        policies=policies,
    )
    policy_results = final_evaluation["policy_results"]
    unauthorized_policies = sum(item["status"] != "authorized" for item in policy_results)
    transitions_verified = sum(item["status"] == "trusted_rotation" for item in transitions)
    expired_intermediates = sum(item["expired_at_evaluation"] for item in root_results[:-1])
    final_result = root_results[-1]

    all_source_errors = bool(anchor_source_errors) or any(
        item["source_errors"] for item in root_results
    )
    transition_statuses = {item["status"] for item in transitions}
    final_version = _plain_int(final_root.get("version"))
    if all_source_errors:
        status = "invalid_chain_evidence"
    elif "rollback_detected" in transition_statuses:
        status = "rollback_detected"
    elif "version_gap_detected" in transition_statuses:
        status = "version_gap_detected"
    elif transition_statuses - {"trusted_rotation"}:
        status = "trust_discontinuity"
    elif anchor_mode == "none":
        status = "untrusted_bootstrap"
    elif anchor_errors:
        status = "trust_discontinuity"
    elif minimum_final_version is not None and (
        final_version is None or final_version < minimum_final_version
    ):
        status = "final_version_not_reached"
        chain_errors.append("final root is below the caller's minimum required version")
    elif final_result["not_yet_valid_at_evaluation"]:
        status = "not_yet_valid_final_root"
        chain_errors.append("final trust root is not yet valid at the evaluation time")
    elif final_result["expired_at_evaluation"]:
        status = "expired_final_root"
        chain_errors.append("final trust root is expired at the evaluation time")
    elif unauthorized_policies:
        status = "policy_not_authorized"
    else:
        status = "trusted_chain"

    for transition in transitions:
        if transition["status"] != "trusted_rotation":
            chain_errors.extend(
                f"transition {transition['transition_index']}: {message}"
                for message in transition["source_errors"] + transition["trust_errors"]
            )

    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "evaluation_time": evaluation_time,
        "anchor": {
            "mode": anchor_mode,
            "expected_root_sha256": expected_root_sha256,
            "expected_trust_domain": expected_trust_domain,
            "minimum_final_version": minimum_final_version,
            "anchor_source_errors": anchor_source_errors,
            "anchor_errors": anchor_errors,
            "expired_at_evaluation": _expired(anchor_root, evaluation_time),
        },
        "trusted_root": deepcopy(dict(trusted_root)) if trusted_root is not None else None,
        "root_inputs": root_inputs,
        "policy_inputs": [deepcopy(dict(item)) for item in policies],
        "root_results": root_results,
        "transitions": transitions,
        "policy_results": policy_results,
        "chain_errors": list(dict.fromkeys(chain_errors)),
        "summary": {
            "status": status,
            "anchor_version": _plain_int(anchor_root.get("version")),
            "final_version": final_version,
            "roots_supplied": len(root_inputs),
            "root_limit": MAX_CHAIN_ROOTS,
            "transitions_required": len(transitions),
            "transitions_verified": transitions_verified,
            "expired_intermediate_roots": expired_intermediates,
            "authorized_policies": len(policy_results) - unauthorized_policies,
            "unauthorized_policies": unauthorized_policies,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_trust_root_chain_report(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Recompute a saved chain report from its fully embedded inputs."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceTrustRootChain report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    anchor = report.get("anchor")
    if not isinstance(anchor, Mapping):
        errors.append("report anchor must be an object")
        return tuple(dict.fromkeys(errors))
    try:
        expected = evaluate_trust_root_chain(
            report.get("root_inputs", []),
            evaluation_time=report.get("evaluation_time"),
            trusted_root=report.get("trusted_root"),
            expected_root_sha256=anchor.get("expected_root_sha256"),
            expected_trust_domain=anchor.get("expected_trust_domain"),
            minimum_final_version=anchor.get("minimum_final_version"),
            policies=report.get("policy_inputs", []),
        )
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"TrustRootChain report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("AssuranceTrustRootChain report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _historical_evaluation_time(root: Mapping[str, Any], fallback: int) -> int:
    issued_at = _plain_int(root.get("issued_at"))
    expires_at = _plain_int(root.get("expires_at"))
    if issued_at is not None and expires_at is not None and issued_at < expires_at:
        return issued_at
    return fallback


def _plain_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _digest_or_none(value: Any) -> str | None:
    if isinstance(value, str) and len(value) == 64:
        return value
    return None


def _expired(root: Mapping[str, Any], evaluation_time: int) -> bool:
    expires_at = _plain_int(root.get("expires_at"))
    return expires_at is not None and evaluation_time >= expires_at


__all__ = [
    "ANALYZER",
    "CLAIM_BOUNDARY",
    "MAX_CHAIN_ROOTS",
    "PROTOCOL_VERSION",
    "REPORT_TYPE",
    "SIGNATURE_SCHEMES",
    "TRUSTED_CHAIN_STATUSES",
    "evaluate_trust_root_chain",
    "verify_trust_root_chain_report",
]
