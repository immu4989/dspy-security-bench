"""Offline, independently signed bounded-time evidence for assurance artifacts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.proof import (
    _sign_payload,
    _validate_key,
    _verify_signature,
    key_descriptor,
)
from dspy_security_bench.mission.loader import canonical_sha256

POLICY_TYPE = "dspy-security-bench-assurance-time-quorum-policy"
REPORT_TYPE = "AssuranceLedger AssuranceTimeQuorum / Independently bounded time evidence"
PROTOCOL_VERSION = "assuranceledger-time-quorum-v1"
ANALYZER = "deterministic-independent-bounded-time-analyzer-v1"
TRUSTED_STATUS = "bounded_time_corroborated"
MAX_SOURCES = 50
MAX_RECEIPTS = 50
CLAIM_BOUNDARY = (
    "AssuranceTimeQuorum verifies policy-pinned Ed25519 signatures from distinct declared "
    "time-source organizations over one exact artifact digest and caller nonce. It computes "
    "only the intersection of source-declared uncertainty intervals and rejects divergent, "
    "over-wide, replayed, rebound, or insufficiently diverse evidence. A passing report is "
    "portable bounded-time evidence for that request, not a precise clock or operational action."
)
LIMITATIONS = (
    "Source and organization identifiers are policy assertions; signatures do not prove legal identity, operational independence, clock quality, or secure key custody.",
    "Freshness depends on the caller generating and independently retaining an unpredictable request nonce and the exact pinned policy digest.",
    "The output is a conservative intersection of source-declared intervals, not a consensus average, UTC realization, clock synchronization command, or proof that every source is correct.",
    "This AssuranceLedger profile is not RFC 3161, Roughtime, NTP, PTP, a time-stamping authority, a FIPS validation, or a replacement for deployment-owned authoritative time services.",
    "The analyzer performs no network access, clock adjustment, key generation, notification, deployment, authorization, risk acceptance, or automatic remediation.",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[A-Za-z0-9._:-]{16,200}\Z")
_POLICY_FIELDS = {
    "schema_version",
    "policy_type",
    "protocol_version",
    "quorum_id",
    "trust_domain",
    "sources",
    "minimum_sources",
    "minimum_distinct_organizations",
    "maximum_radius_seconds",
    "maximum_interval_width_seconds",
    "claim_boundary",
    "policy_sha256",
}
_RECEIPT_FIELDS = {"statement", "time_source_signature"}
_STATEMENT_FIELDS = {
    "protocol_version",
    "time_policy_sha256",
    "trust_domain",
    "subject_sha256",
    "request_nonce",
    "source_id",
    "source_organization_id",
    "source_key_sha256",
    "midpoint_unix",
    "radius_seconds",
    "lower_bound_unix",
    "upper_bound_unix",
}
_CHECKS = (
    ("ATQ001", "The exact time policy is independently pinned"),
    ("ATQ002", "The time policy structure, keys, and digest are valid"),
    ("ATQ003", "Every receipt has the exact bounded-time statement shape"),
    ("ATQ004", "Every receipt binds the exact subject and fresh request nonce"),
    ("ATQ005", "Every receipt signer and organization match the policy"),
    ("ATQ006", "Every time-source Ed25519 signature verifies"),
    ("ATQ007", "Every uncertainty radius and derived interval are policy-bounded"),
    ("ATQ008", "The minimum number of unique time sources is satisfied"),
    ("ATQ009", "The minimum distinct-organization threshold is satisfied"),
    ("ATQ010", "The source intervals overlap within the maximum width"),
)


def time_source_descriptor(
    public_key_path: str | Path,
    *,
    source_id: str,
    organization_id: str,
) -> dict[str, str]:
    """Describe one Ed25519 public key for a time-source policy."""

    return key_descriptor(
        public_key_path,
        entity_id=source_id,
        organization_id=organization_id,
    )


def build_time_policy(
    sources: Sequence[Mapping[str, Any]],
    *,
    quorum_id: str,
    trust_domain: str,
    minimum_sources: int,
    minimum_distinct_organizations: int,
    maximum_radius_seconds: int,
    maximum_interval_width_seconds: int,
) -> dict[str, Any]:
    """Build a self-digested time policy ready for out-of-band pinning."""

    policy: dict[str, Any] = {
        "schema_version": 1,
        "policy_type": POLICY_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "quorum_id": quorum_id,
        "trust_domain": trust_domain,
        "sources": sorted(
            (deepcopy(dict(item)) for item in sources),
            key=lambda item: item["entity_id"],
        ),
        "minimum_sources": minimum_sources,
        "minimum_distinct_organizations": minimum_distinct_organizations,
        "maximum_radius_seconds": maximum_radius_seconds,
        "maximum_interval_width_seconds": maximum_interval_width_seconds,
        "claim_boundary": CLAIM_BOUNDARY,
    }
    policy["policy_sha256"] = canonical_sha256(policy)
    if errors := validate_time_policy(policy):
        raise ValueError("invalid AssuranceTimeQuorum policy: " + "; ".join(errors))
    return policy


def validate_time_policy(policy: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate the exact v1 time policy and recompute its digest."""

    errors: list[str] = []
    if not isinstance(policy, Mapping):
        return ("time policy must be an object",)
    _exact(policy, _POLICY_FIELDS, "time policy", errors)
    if (
        policy.get("schema_version") != 1
        or policy.get("policy_type") != POLICY_TYPE
        or policy.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("time policy metadata does not match AssuranceTimeQuorum v1")
    _identifier(policy.get("quorum_id"), "quorum_id", errors)
    domain = policy.get("trust_domain")
    if not isinstance(domain, str) or not domain.strip() or len(domain) > 300:
        errors.append("trust_domain must be a non-empty string of at most 300 characters")
    sources = policy.get("sources")
    if not isinstance(sources, list) or not 2 <= len(sources) <= MAX_SOURCES:
        errors.append(f"sources must contain 2 to {MAX_SOURCES} entries")
        sources = []
    elif sources != sorted(
        sources,
        key=lambda item: item.get("entity_id", "") if isinstance(item, Mapping) else "",
    ):
        errors.append("sources must be sorted by entity_id")
    source_ids: set[str] = set()
    key_ids: set[str] = set()
    organizations: set[str] = set()
    for index, source in enumerate(sources):
        item = _validate_key(source, f"sources[{index}]", errors)
        if item is None:
            continue
        source_id = item.get("entity_id")
        key_id = item.get("public_key_sha256")
        organization = item.get("organization_id")
        if source_id in source_ids:
            errors.append(f"duplicate source entity_id {source_id!r}")
        if key_id in key_ids:
            errors.append(f"duplicate source public key {key_id!r}")
        source_ids.add(str(source_id))
        key_ids.add(str(key_id))
        organizations.add(str(organization))
    minimum = _positive_int(policy.get("minimum_sources"), "minimum_sources", errors)
    organization_minimum = _positive_int(
        policy.get("minimum_distinct_organizations"),
        "minimum_distinct_organizations",
        errors,
    )
    maximum_radius = _positive_int(
        policy.get("maximum_radius_seconds"), "maximum_radius_seconds", errors
    )
    maximum_width = _positive_int(
        policy.get("maximum_interval_width_seconds"),
        "maximum_interval_width_seconds",
        errors,
    )
    if minimum is not None and not 2 <= minimum <= len(sources):
        errors.append("minimum_sources is outside the source bound")
    if organization_minimum is not None and not 2 <= organization_minimum <= len(
        organizations
    ):
        errors.append("minimum_distinct_organizations cannot be met")
    if maximum_radius is not None and maximum_radius > 86_400:
        errors.append("maximum_radius_seconds cannot exceed one day")
    if maximum_width is not None and maximum_width > 172_800:
        errors.append("maximum_interval_width_seconds cannot exceed two days")
    if policy.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match AssuranceTimeQuorum v1")
    unsigned = dict(policy)
    claimed = unsigned.pop("policy_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("time policy_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("time policy is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def create_time_receipt(
    policy: Mapping[str, Any],
    private_key_path: str | Path,
    *,
    source_id: str,
    subject_sha256: str,
    request_nonce: str,
    midpoint_unix: int,
    radius_seconds: int,
) -> dict[str, Any]:
    """Sign one nonce-bound bounded-time observation for an exact subject digest."""

    if errors := validate_time_policy(policy):
        raise ValueError("invalid AssuranceTimeQuorum policy: " + "; ".join(errors))
    _require_digest(subject_sha256, "subject_sha256")
    _require_nonce(request_nonce)
    midpoint = _require_nonnegative_int(midpoint_unix, "midpoint_unix")
    radius = _require_positive_int(radius_seconds, "radius_seconds")
    if radius > policy["maximum_radius_seconds"]:
        raise ValueError("radius_seconds exceeds the time policy maximum")
    source_map = {item["entity_id"]: item for item in policy["sources"]}
    source = source_map.get(source_id)
    if source is None:
        raise ValueError("source_id is not authorized by the time policy")
    statement = {
        "protocol_version": PROTOCOL_VERSION,
        "time_policy_sha256": policy["policy_sha256"],
        "trust_domain": policy["trust_domain"],
        "subject_sha256": subject_sha256,
        "request_nonce": request_nonce,
        "source_id": source_id,
        "source_organization_id": source["organization_id"],
        "source_key_sha256": source["public_key_sha256"],
        "midpoint_unix": midpoint,
        "radius_seconds": radius,
        "lower_bound_unix": midpoint - radius,
        "upper_bound_unix": midpoint + radius,
    }
    if statement["lower_bound_unix"] < 0:
        raise ValueError("time interval cannot begin before the Unix epoch")
    receipt = {
        "statement": statement,
        "time_source_signature": _sign_payload(
            statement,
            private_key_path,
            source,
            signer_id=source_id,
        ),
    }
    checks = _verify_receipt(
        policy,
        receipt,
        0,
        expected_subject_sha256=subject_sha256,
        expected_request_nonce=request_nonce,
    )
    errors = _flatten(checks)
    if errors:
        raise ValueError("generated time receipt is invalid: " + "; ".join(errors))
    return receipt


def evaluate_time_quorum(
    policy: Mapping[str, Any],
    receipts: Sequence[Mapping[str, Any]],
    *,
    expected_policy_sha256: str,
    expected_subject_sha256: str,
    expected_request_nonce: str,
) -> dict[str, Any]:
    """Verify signed intervals and compute their conservative overlap."""

    _require_digest(expected_policy_sha256, "expected_policy_sha256")
    _require_digest(expected_subject_sha256, "expected_subject_sha256")
    _require_nonce(expected_request_nonce)
    if not isinstance(receipts, list) or not 1 <= len(receipts) <= MAX_RECEIPTS:
        raise ValueError(f"receipts must contain 1 to {MAX_RECEIPTS} entries")

    policy_errors = list(validate_time_policy(policy))
    policy_pinned = policy.get("policy_sha256") == expected_policy_sha256
    receipt_results: list[dict[str, Any]] = []
    valid: list[Mapping[str, Any]] = []
    all_rule_errors = {rule_id: [] for rule_id, _ in _CHECKS}
    all_rule_errors["ATQ002"].extend(policy_errors)
    if not policy_pinned:
        all_rule_errors["ATQ001"].append(
            "time policy digest does not match the independently supplied pin"
        )

    for index, receipt in enumerate(receipts):
        checks = _verify_receipt(
            policy,
            receipt,
            index,
            expected_subject_sha256=expected_subject_sha256,
            expected_request_nonce=expected_request_nonce,
        )
        for rule_id, errors in checks.items():
            all_rule_errors[rule_id].extend(errors)
        flat_errors = _flatten(checks)
        statement = receipt.get("statement", {}) if isinstance(receipt, Mapping) else {}
        receipt_results.append(
            {
                "receipt_index": index,
                "source_id": statement.get("source_id") if isinstance(statement, Mapping) else None,
                "source_organization_id": (
                    statement.get("source_organization_id")
                    if isinstance(statement, Mapping)
                    else None
                ),
                "lower_bound_unix": (
                    statement.get("lower_bound_unix") if isinstance(statement, Mapping) else None
                ),
                "upper_bound_unix": (
                    statement.get("upper_bound_unix") if isinstance(statement, Mapping) else None
                ),
                "status": "valid" if not flat_errors else "invalid",
                "errors": flat_errors,
            }
        )
        if not flat_errors:
            valid.append(receipt)

    source_ids = [item["statement"]["source_id"] for item in valid]
    organizations = {item["statement"]["source_organization_id"] for item in valid}
    unique_sources = len(set(source_ids)) == len(source_ids)
    enough_sources = unique_sources and len(valid) >= policy.get(
        "minimum_sources", MAX_RECEIPTS + 1
    )
    enough_organizations = len(organizations) >= policy.get(
        "minimum_distinct_organizations", MAX_RECEIPTS + 1
    )
    if not unique_sources:
        all_rule_errors["ATQ008"].append("one time source submitted more than one receipt")
    if len(valid) < policy.get("minimum_sources", MAX_RECEIPTS + 1):
        all_rule_errors["ATQ008"].append("minimum valid time-source threshold is not met")
    if not enough_organizations:
        all_rule_errors["ATQ009"].append(
            "minimum distinct time-source organization threshold is not met"
        )

    lower_bound = max((item["statement"]["lower_bound_unix"] for item in valid), default=None)
    upper_bound = min((item["statement"]["upper_bound_unix"] for item in valid), default=None)
    interval_width = (
        upper_bound - lower_bound
        if lower_bound is not None and upper_bound is not None and lower_bound <= upper_bound
        else None
    )
    intervals_overlap = interval_width is not None
    width_bounded = intervals_overlap and interval_width <= policy.get(
        "maximum_interval_width_seconds", -1
    )
    if not intervals_overlap:
        all_rule_errors["ATQ010"].append("valid source uncertainty intervals do not overlap")
    elif not width_bounded:
        all_rule_errors["ATQ010"].append(
            "conservative interval exceeds maximum_interval_width_seconds"
        )

    request_mismatch = bool(all_rule_errors["ATQ004"])
    evidence_errors = bool(policy_errors) or any(
        all_rule_errors[rule_id]
        for rule_id in ("ATQ003", "ATQ005", "ATQ006", "ATQ007")
    )
    if evidence_errors:
        status = "invalid_time_evidence"
    elif not policy_pinned:
        status = "time_policy_not_pinned"
    elif request_mismatch:
        status = "time_request_mismatch"
    elif not enough_sources:
        status = "insufficient_time_sources"
    elif not enough_organizations:
        status = "insufficient_time_source_diversity"
    elif not intervals_overlap:
        status = "time_sources_inconsistent"
    elif not width_bounded:
        status = "time_uncertainty_too_wide"
    else:
        status = TRUSTED_STATUS

    findings = []
    for rule_id, title in _CHECKS:
        errors = list(dict.fromkeys(all_rule_errors[rule_id]))
        findings.append(
            {
                "rule_id": rule_id,
                "title": title,
                "status": "passed" if not errors else "failed",
                "detail": "verified" if not errors else "; ".join(errors),
                "receipt_indexes": list(range(len(receipts))),
            }
        )
    failed = sum(item["status"] == "failed" for item in findings)
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "time_policy": deepcopy(dict(policy)),
        "expectations": {
            "expected_policy_sha256": expected_policy_sha256,
            "expected_subject_sha256": expected_subject_sha256,
            "expected_request_nonce": expected_request_nonce,
        },
        "receipts": [deepcopy(dict(item)) for item in receipts],
        "policy_errors": policy_errors,
        "receipt_results": receipt_results,
        "findings": findings,
        "conservative_interval": {
            "lower_bound_unix": lower_bound if intervals_overlap else None,
            "upper_bound_unix": upper_bound if intervals_overlap else None,
            "width_seconds": interval_width,
        },
        "summary": {
            "status": status,
            "submitted_receipts": len(receipts),
            "valid_receipts": len(valid),
            "distinct_sources": len(set(source_ids)),
            "distinct_organizations": len(organizations),
            "passed_checks": len(findings) - failed,
            "failed_checks": failed,
            "content_fields_processed": 0,
            "clock_adjustments": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_time_quorum_report(
    report: Mapping[str, Any],
    *,
    expected_policy_sha256: str | None = None,
    expected_subject_sha256: str | None = None,
    expected_request_nonce: str | None = None,
) -> tuple[str, ...]:
    """Recompute a report and optionally enforce caller-retained expectations."""

    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceTimeQuorum report")
    expectations = report.get("expectations")
    if not isinstance(expectations, Mapping):
        errors.append("report expectations must be an object")
        expectations = {}
    external = (
        ("policy", expected_policy_sha256, expectations.get("expected_policy_sha256")),
        ("subject", expected_subject_sha256, expectations.get("expected_subject_sha256")),
        ("request nonce", expected_request_nonce, expectations.get("expected_request_nonce")),
    )
    for label, supplied, recorded in external:
        if supplied is not None and supplied != recorded:
            errors.append(f"report {label} does not match the caller-retained expectation")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = evaluate_time_quorum(
            report.get("time_policy", {}),
            report.get("receipts", []),
            expected_policy_sha256=expectations.get("expected_policy_sha256", ""),
            expected_subject_sha256=expectations.get("expected_subject_sha256", ""),
            expected_request_nonce=expectations.get("expected_request_nonce", ""),
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("AssuranceTimeQuorum report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _verify_receipt(
    policy: Mapping[str, Any],
    receipt: Any,
    index: int,
    *,
    expected_subject_sha256: str,
    expected_request_nonce: str,
) -> dict[str, list[str]]:
    checks = {rule_id: [] for rule_id, _ in _CHECKS}
    label = f"receipts[{index}]"
    if not isinstance(receipt, Mapping):
        checks["ATQ003"].append(f"{label} must be an object")
        return checks
    _exact(receipt, _RECEIPT_FIELDS, label, checks["ATQ003"])
    statement = receipt.get("statement")
    if not isinstance(statement, Mapping):
        checks["ATQ003"].append(f"{label}.statement must be an object")
        return checks
    _exact(statement, _STATEMENT_FIELDS, f"{label}.statement", checks["ATQ003"])
    if statement.get("protocol_version") != PROTOCOL_VERSION:
        checks["ATQ003"].append(f"{label}.statement protocol_version is invalid")
    if statement.get("time_policy_sha256") != policy.get("policy_sha256"):
        checks["ATQ003"].append(f"{label}.statement time policy does not match")
    if statement.get("trust_domain") != policy.get("trust_domain"):
        checks["ATQ003"].append(f"{label}.statement trust_domain does not match")
    if statement.get("subject_sha256") != expected_subject_sha256:
        checks["ATQ004"].append(f"{label}.statement subject does not match the request")
    if statement.get("request_nonce") != expected_request_nonce:
        checks["ATQ004"].append(f"{label}.statement nonce does not match the request")
    if not _is_digest(statement.get("subject_sha256")):
        checks["ATQ003"].append(f"{label}.statement subject_sha256 is invalid")
    if not _is_nonce(statement.get("request_nonce")):
        checks["ATQ003"].append(f"{label}.statement request_nonce is invalid")

    source_map = {
        item["entity_id"]: item
        for item in policy.get("sources", [])
        if isinstance(item, Mapping) and "entity_id" in item
    }
    source = source_map.get(statement.get("source_id"))
    if source is None:
        checks["ATQ005"].append(f"{label}.statement source is not policy-authorized")
        source = {}
    else:
        if statement.get("source_organization_id") != source.get("organization_id"):
            checks["ATQ005"].append(f"{label}.statement source organization does not match")
        if statement.get("source_key_sha256") != source.get("public_key_sha256"):
            checks["ATQ005"].append(f"{label}.statement source key does not match")
    checks["ATQ006"].extend(
        _verify_signature(
            statement,
            receipt.get("time_source_signature"),
            source,
            expected_signer=str(statement.get("source_id")),
            label=f"{label}.time_source_signature",
        )
    )
    midpoint = _nonnegative_int(
        statement.get("midpoint_unix"), f"{label}.statement.midpoint_unix", checks["ATQ007"]
    )
    radius = _positive_int(
        statement.get("radius_seconds"), f"{label}.statement.radius_seconds", checks["ATQ007"]
    )
    lower = _nonnegative_int(
        statement.get("lower_bound_unix"),
        f"{label}.statement.lower_bound_unix",
        checks["ATQ007"],
    )
    upper = _nonnegative_int(
        statement.get("upper_bound_unix"),
        f"{label}.statement.upper_bound_unix",
        checks["ATQ007"],
    )
    if radius is not None and radius > policy.get("maximum_radius_seconds", -1):
        checks["ATQ007"].append(f"{label}.statement radius exceeds the policy maximum")
    if None not in (midpoint, radius, lower, upper) and (
        lower != midpoint - radius or upper != midpoint + radius
    ):
        checks["ATQ007"].append(f"{label}.statement interval does not derive from midpoint/radius")
    return checks


def _flatten(checks: Mapping[str, Sequence[str]]) -> list[str]:
    return list(dict.fromkeys(error for errors in checks.values() for error in errors))


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    if missing := sorted(expected - set(value)):
        errors.append(f"{label} is missing fields: {', '.join(missing)}")
    if extra := sorted(set(value) - expected):
        errors.append(f"{label} has unexpected fields: {', '.join(extra)}")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST.fullmatch(value))


def _is_nonce(value: Any) -> bool:
    return isinstance(value, str) and bool(_NONCE.fullmatch(value))


def _positive_int(value: Any, label: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        errors.append(f"{label} must be a positive integer")
        return None
    return value


def _nonnegative_int(value: Any, label: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        errors.append(f"{label} must be a non-negative integer")
        return None
    return value


def _require_digest(value: Any, label: str) -> str:
    if not _is_digest(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_nonce(value: Any) -> str:
    if not _is_nonce(value):
        raise ValueError("request_nonce must be 16 to 200 safe printable characters")
    return value


def _require_positive_int(value: Any, label: str) -> int:
    errors: list[str] = []
    result = _positive_int(value, label, errors)
    if result is None:
        raise ValueError(errors[0])
    return result


def _require_nonnegative_int(value: Any, label: str) -> int:
    errors: list[str] = []
    result = _nonnegative_int(value, label, errors)
    if result is None:
        raise ValueError(errors[0])
    return result
