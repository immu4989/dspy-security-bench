"""Offline, independently signed observations of AssuranceTrustRoot distribution."""

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
from dspy_security_bench.ledger.trust_root import validate_trust_root
from dspy_security_bench.mission.loader import canonical_sha256

POLICY_TYPE = "dspy-security-bench-assurance-root-view-policy"
REPORT_TYPE = "AssuranceLedger RootViewQuorum / Independently observed root distribution"
PROTOCOL_VERSION = "assuranceledger-root-view-quorum-v1"
ANALYZER = "deterministic-independent-root-view-analyzer-v1"
TRUSTED_STATUS = "root_view_corroborated"
MAX_OBSERVERS = 50
MAX_RECEIPTS = 50
CLAIM_BOUNDARY = (
    "RootViewQuorum verifies policy-pinned Ed25519 observations from distinct declared "
    "organizations over one candidate AssuranceTrustRoot and fresh caller nonce. It "
    "corroborates only the views supplied for that challenge and makes authenticated "
    "observations of a self-consistent same-version conflict or higher-version root "
    "non-outvotable. A passing report is bounded "
    "distribution-view evidence, not proof of global freshness or root trust."
)
LIMITATIONS = (
    "Observer and organization identifiers are policy assertions; signatures do not prove legal identity, operational independence, complete monitoring, or secure key custody.",
    "Freshness depends on the caller generating and independently retaining an unpredictable nonce and the exact pinned observer-policy digest.",
    "A higher-version receipt proves that an authorized observer signed a self-consistent root object; it does not by itself prove continuity from the candidate or that the root was globally deployed.",
    "A passing quorum cannot exclude an undisclosed view held outside the selected observers, a partition affecting all selected observers, or collusion sufficient to satisfy the policy.",
    "The protocol is not TUF, C2SP transparency-witness, Key Transparency, SCITT, PKI, trust-store, or software-update compatibility.",
    "The analyzer performs no network access, root installation, key operation, notification, revocation, deployment, authorization, risk acceptance, or automatic remediation.",
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
    "observers",
    "minimum_observers",
    "minimum_distinct_organizations",
    "claim_boundary",
    "policy_sha256",
}
_RECEIPT_FIELDS = {"statement", "observed_root", "observer_signature"}
_STATEMENT_FIELDS = {
    "protocol_version",
    "root_view_policy_sha256",
    "trust_domain",
    "candidate_root_sha256",
    "request_nonce",
    "observer_id",
    "observer_organization_id",
    "observer_key_sha256",
    "observed_root_sha256",
    "observed_root_version",
}
_CHECKS = (
    ("ARV001", "The exact root-view policy is independently pinned"),
    ("ARV002", "The root-view policy structure, keys, and digest are valid"),
    ("ARV003", "The candidate root is self-consistent and in the expected domain"),
    ("ARV004", "Every receipt has the exact root-view statement shape"),
    ("ARV005", "Every receipt binds the candidate root and fresh request nonce"),
    ("ARV006", "Every observer identity, organization, key, and signature verify"),
    ("ARV007", "Every embedded observed root recomputes and matches its statement"),
    ("ARV008", "The minimum number of unique matching observers is satisfied"),
    ("ARV009", "The matching-observer organization threshold is satisfied"),
    (
        "ARV010",
        "No authenticated self-consistent same-version conflict or higher root is reported",
    ),
)


def root_view_observer_descriptor(
    public_key_path: str | Path,
    *,
    observer_id: str,
    organization_id: str,
) -> dict[str, str]:
    """Describe one Ed25519 key for a root-view observer policy."""

    return key_descriptor(
        public_key_path,
        entity_id=observer_id,
        organization_id=organization_id,
    )


def build_root_view_policy(
    observers: Sequence[Mapping[str, Any]],
    *,
    quorum_id: str,
    trust_domain: str,
    minimum_observers: int,
    minimum_distinct_organizations: int,
) -> dict[str, Any]:
    """Build a self-digested observer policy ready for independent pinning."""

    policy: dict[str, Any] = {
        "schema_version": 1,
        "policy_type": POLICY_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "quorum_id": quorum_id,
        "trust_domain": trust_domain,
        "observers": sorted(
            (deepcopy(dict(item)) for item in observers),
            key=lambda item: item["entity_id"],
        ),
        "minimum_observers": minimum_observers,
        "minimum_distinct_organizations": minimum_distinct_organizations,
        "claim_boundary": CLAIM_BOUNDARY,
    }
    policy["policy_sha256"] = canonical_sha256(policy)
    if errors := validate_root_view_policy(policy):
        raise ValueError("invalid RootViewQuorum policy: " + "; ".join(errors))
    return policy


def validate_root_view_policy(policy: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate the exact v1 observer policy and recompute its digest."""

    errors: list[str] = []
    if not isinstance(policy, Mapping):
        return ("root-view policy must be an object",)
    _exact(policy, _POLICY_FIELDS, "root-view policy", errors)
    if (
        policy.get("schema_version") != 1
        or policy.get("policy_type") != POLICY_TYPE
        or policy.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("root-view policy metadata does not match RootViewQuorum v1")
    _identifier(policy.get("quorum_id"), "quorum_id", errors)
    domain = policy.get("trust_domain")
    if not isinstance(domain, str) or not domain.strip() or len(domain) > 300:
        errors.append("trust_domain must be a non-empty string of at most 300 characters")
    observers = policy.get("observers")
    if not isinstance(observers, list) or not 2 <= len(observers) <= MAX_OBSERVERS:
        errors.append(f"observers must contain 2 to {MAX_OBSERVERS} entries")
        observers = []
    elif observers != sorted(
        observers,
        key=lambda item: item.get("entity_id", "") if isinstance(item, Mapping) else "",
    ):
        errors.append("observers must be sorted by entity_id")
    observer_ids: set[str] = set()
    key_ids: set[str] = set()
    organizations: set[str] = set()
    for index, observer in enumerate(observers):
        item = _validate_key(observer, f"observers[{index}]", errors)
        if item is None:
            continue
        observer_id = item.get("entity_id")
        key_id = item.get("public_key_sha256")
        organization = item.get("organization_id")
        if observer_id in observer_ids:
            errors.append(f"duplicate observer entity_id {observer_id!r}")
        if key_id in key_ids:
            errors.append(f"duplicate observer public key {key_id!r}")
        observer_ids.add(str(observer_id))
        key_ids.add(str(key_id))
        organizations.add(str(organization))
    minimum = _positive_int(policy.get("minimum_observers"), "minimum_observers", errors)
    organization_minimum = _positive_int(
        policy.get("minimum_distinct_organizations"),
        "minimum_distinct_organizations",
        errors,
    )
    if minimum is not None and not 2 <= minimum <= len(observers):
        errors.append("minimum_observers is outside the observer bound")
    if organization_minimum is not None and not 2 <= organization_minimum <= len(
        organizations
    ):
        errors.append("minimum_distinct_organizations cannot be met")
    if policy.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match RootViewQuorum v1")
    unsigned = dict(policy)
    claimed = unsigned.pop("policy_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("root-view policy_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("root-view policy is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def create_root_view_receipt(
    policy: Mapping[str, Any],
    private_key_path: str | Path,
    observed_root: Mapping[str, Any],
    *,
    observer_id: str,
    candidate_root_sha256: str,
    request_nonce: str,
) -> dict[str, Any]:
    """Sign one nonce-bound observation of an exact AssuranceTrustRoot object."""

    if errors := validate_root_view_policy(policy):
        raise ValueError("invalid RootViewQuorum policy: " + "; ".join(errors))
    _require_digest(candidate_root_sha256, "candidate_root_sha256")
    _require_nonce(request_nonce)
    root_errors = validate_trust_root(observed_root)
    if root_errors:
        raise ValueError("invalid observed AssuranceTrustRoot: " + "; ".join(root_errors))
    if observed_root.get("trust_domain") != policy["trust_domain"]:
        raise ValueError("observed root trust_domain does not match the policy")
    observer_map = {item["entity_id"]: item for item in policy["observers"]}
    observer = observer_map.get(observer_id)
    if observer is None:
        raise ValueError("observer_id is not authorized by the root-view policy")
    statement = {
        "protocol_version": PROTOCOL_VERSION,
        "root_view_policy_sha256": policy["policy_sha256"],
        "trust_domain": policy["trust_domain"],
        "candidate_root_sha256": candidate_root_sha256,
        "request_nonce": request_nonce,
        "observer_id": observer_id,
        "observer_organization_id": observer["organization_id"],
        "observer_key_sha256": observer["public_key_sha256"],
        "observed_root_sha256": observed_root["root_sha256"],
        "observed_root_version": observed_root["version"],
    }
    receipt = {
        "statement": statement,
        "observed_root": deepcopy(dict(observed_root)),
        "observer_signature": _sign_payload(
            statement,
            private_key_path,
            observer,
            signer_id=observer_id,
        ),
    }
    errors = _flatten(
        _verify_receipt(
            policy,
            receipt,
            0,
            candidate_root_sha256=candidate_root_sha256,
            request_nonce=request_nonce,
        )
    )
    if errors:
        raise ValueError("generated root-view receipt is invalid: " + "; ".join(errors))
    return receipt


def evaluate_root_view_quorum(
    policy: Mapping[str, Any],
    candidate_root: Mapping[str, Any],
    receipts: Sequence[Mapping[str, Any]],
    *,
    expected_policy_sha256: str,
    expected_request_nonce: str,
) -> dict[str, Any]:
    """Corroborate a candidate root and surface newer or conflicting signed views."""

    _require_digest(expected_policy_sha256, "expected_policy_sha256")
    _require_nonce(expected_request_nonce)
    if not isinstance(receipts, list) or not 1 <= len(receipts) <= MAX_RECEIPTS:
        raise ValueError(f"receipts must contain 1 to {MAX_RECEIPTS} entries")

    policy_errors = list(validate_root_view_policy(policy))
    candidate_errors = list(validate_trust_root(candidate_root))
    policy_pinned = policy.get("policy_sha256") == expected_policy_sha256
    candidate = candidate_root if isinstance(candidate_root, Mapping) else {}
    candidate_digest = candidate.get("root_sha256")
    candidate_version = _plain_positive_int(candidate.get("version"))
    if candidate.get("trust_domain") != policy.get("trust_domain"):
        candidate_errors.append("candidate trust_domain does not match the root-view policy")

    rule_errors = {rule_id: [] for rule_id, _ in _CHECKS}
    rule_errors["ARV002"].extend(policy_errors)
    rule_errors["ARV003"].extend(candidate_errors)
    if not policy_pinned:
        rule_errors["ARV001"].append(
            "root-view policy digest does not match the independently supplied pin"
        )

    receipt_results: list[dict[str, Any]] = []
    valid: list[Mapping[str, Any]] = []
    for index, receipt in enumerate(receipts):
        checks = _verify_receipt(
            policy,
            receipt,
            index,
            candidate_root_sha256=str(candidate_digest),
            request_nonce=expected_request_nonce,
        )
        for rule_id, errors in checks.items():
            rule_errors[rule_id].extend(errors)
        flat_errors = _flatten(checks)
        statement = receipt.get("statement", {}) if isinstance(receipt, Mapping) else {}
        observed_digest = (
            statement.get("observed_root_sha256") if isinstance(statement, Mapping) else None
        )
        observed_version = (
            _plain_positive_int(statement.get("observed_root_version"))
            if isinstance(statement, Mapping)
            else None
        )
        classification = _classification(
            candidate_digest,
            candidate_version,
            observed_digest,
            observed_version,
        )
        receipt_results.append(
            {
                "receipt_index": index,
                "observer_id": (
                    statement.get("observer_id") if isinstance(statement, Mapping) else None
                ),
                "observer_organization_id": (
                    statement.get("observer_organization_id")
                    if isinstance(statement, Mapping)
                    else None
                ),
                "observed_root_sha256": observed_digest,
                "observed_root_version": observed_version,
                "classification": classification if not flat_errors else "invalid",
                "status": "valid" if not flat_errors else "invalid",
                "errors": flat_errors,
            }
        )
        if not flat_errors:
            valid.append(receipt)

    observer_ids = [item["statement"]["observer_id"] for item in valid]
    unique_observers = len(set(observer_ids)) == len(observer_ids)
    if not unique_observers:
        rule_errors["ARV008"].append("one observer submitted more than one valid receipt")

    classified = [item for item in receipt_results if item["status"] == "valid"]
    matching = [item for item in classified if item["classification"] == "matching"]
    matching_ids = {item["observer_id"] for item in matching}
    matching_organizations = {item["observer_organization_id"] for item in matching}
    lagging = [item for item in classified if item["classification"] == "lagging"]
    newer = [item for item in classified if item["classification"] == "newer"]
    conflicts = [
        item for item in classified if item["classification"] == "same_version_conflict"
    ]
    enough_observers = unique_observers and len(matching_ids) >= policy.get(
        "minimum_observers", MAX_RECEIPTS + 1
    )
    enough_organizations = len(matching_organizations) >= policy.get(
        "minimum_distinct_organizations", MAX_RECEIPTS + 1
    )
    if len(matching_ids) < policy.get("minimum_observers", MAX_RECEIPTS + 1):
        rule_errors["ARV008"].append("minimum matching-observer threshold is not met")
    if not enough_organizations:
        rule_errors["ARV009"].append(
            "minimum distinct matching-observer organization threshold is not met"
        )
    if conflicts:
        rule_errors["ARV010"].append(
            "an authorized observer reported a different self-consistent root at the candidate version"
        )
    if newer:
        rule_errors["ARV010"].append(
            "an authorized observer reported a self-consistent root above the candidate version"
        )

    request_mismatch = bool(rule_errors["ARV005"])
    evidence_errors = bool(policy_errors) or bool(candidate_errors) or any(
        rule_errors[rule_id] for rule_id in ("ARV004", "ARV006", "ARV007")
    )
    if evidence_errors:
        status = "invalid_root_view_evidence"
    elif not policy_pinned:
        status = "root_view_policy_not_pinned"
    elif request_mismatch:
        status = "root_view_request_mismatch"
    elif not unique_observers:
        status = "insufficient_root_observers"
    elif conflicts:
        status = "same_version_root_conflict"
    elif newer:
        status = "newer_root_reported"
    elif not enough_observers:
        status = "insufficient_root_observers"
    elif not enough_organizations:
        status = "insufficient_root_observer_diversity"
    else:
        status = TRUSTED_STATUS

    findings = []
    for rule_id, title in _CHECKS:
        errors = list(dict.fromkeys(rule_errors[rule_id]))
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
        "root_view_policy": deepcopy(dict(policy)),
        "candidate_root": deepcopy(dict(candidate)),
        "expectations": {
            "expected_policy_sha256": expected_policy_sha256,
            "expected_request_nonce": expected_request_nonce,
        },
        "receipts": [deepcopy(dict(item)) for item in receipts],
        "policy_errors": policy_errors,
        "candidate_errors": candidate_errors,
        "receipt_results": receipt_results,
        "findings": findings,
        "summary": {
            "status": status,
            "candidate_root_version": candidate_version,
            "submitted_receipts": len(receipts),
            "valid_receipts": len(valid),
            "distinct_observers": len(set(observer_ids)),
            "matching_observers": len(matching_ids),
            "matching_organizations": len(matching_organizations),
            "lagging_observers": len(lagging),
            "newer_root_reports": len(newer),
            "same_version_conflicts": len(conflicts),
            "passed_checks": len(findings) - failed,
            "failed_checks": failed,
            "content_fields_processed": 0,
            "network_requests": 0,
            "roots_installed": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_root_view_report(
    report: Mapping[str, Any],
    *,
    expected_policy_sha256: str | None = None,
    expected_candidate_root_sha256: str | None = None,
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
        errors.append("unsupported RootViewQuorum report")
    expectations = report.get("expectations")
    if not isinstance(expectations, Mapping):
        errors.append("report expectations must be an object")
        expectations = {}
    candidate = report.get("candidate_root")
    candidate_digest = candidate.get("root_sha256") if isinstance(candidate, Mapping) else None
    external = (
        ("policy", expected_policy_sha256, expectations.get("expected_policy_sha256")),
        ("candidate root", expected_candidate_root_sha256, candidate_digest),
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
        expected = evaluate_root_view_quorum(
            report.get("root_view_policy", {}),
            report.get("candidate_root", {}),
            report.get("receipts", []),
            expected_policy_sha256=expectations.get("expected_policy_sha256", ""),
            expected_request_nonce=expectations.get("expected_request_nonce", ""),
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("RootViewQuorum report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _verify_receipt(
    policy: Mapping[str, Any],
    receipt: Any,
    index: int,
    *,
    candidate_root_sha256: str,
    request_nonce: str,
) -> dict[str, list[str]]:
    checks = {rule_id: [] for rule_id, _ in _CHECKS}
    label = f"receipts[{index}]"
    if not isinstance(receipt, Mapping):
        checks["ARV004"].append(f"{label} must be an object")
        return checks
    _exact(receipt, _RECEIPT_FIELDS, label, checks["ARV004"])
    statement = receipt.get("statement")
    if not isinstance(statement, Mapping):
        checks["ARV004"].append(f"{label}.statement must be an object")
        return checks
    _exact(statement, _STATEMENT_FIELDS, f"{label}.statement", checks["ARV004"])
    if statement.get("protocol_version") != PROTOCOL_VERSION:
        checks["ARV004"].append(f"{label}.statement protocol_version is invalid")
    if statement.get("root_view_policy_sha256") != policy.get("policy_sha256"):
        checks["ARV004"].append(f"{label}.statement root-view policy does not match")
    if statement.get("trust_domain") != policy.get("trust_domain"):
        checks["ARV004"].append(f"{label}.statement trust_domain does not match")
    if statement.get("candidate_root_sha256") != candidate_root_sha256:
        checks["ARV005"].append(f"{label}.statement candidate root does not match")
    if statement.get("request_nonce") != request_nonce:
        checks["ARV005"].append(f"{label}.statement nonce does not match the request")
    if not _is_digest(statement.get("candidate_root_sha256")):
        checks["ARV004"].append(f"{label}.statement candidate_root_sha256 is invalid")
    if not _is_nonce(statement.get("request_nonce")):
        checks["ARV004"].append(f"{label}.statement request_nonce is invalid")

    observer_map = {
        item["entity_id"]: item
        for item in policy.get("observers", [])
        if isinstance(item, Mapping) and "entity_id" in item
    }
    observer = observer_map.get(statement.get("observer_id"))
    if observer is None:
        checks["ARV006"].append(f"{label}.statement observer is not policy-authorized")
        observer = {}
    else:
        if statement.get("observer_organization_id") != observer.get("organization_id"):
            checks["ARV006"].append(f"{label}.statement observer organization does not match")
        if statement.get("observer_key_sha256") != observer.get("public_key_sha256"):
            checks["ARV006"].append(f"{label}.statement observer key does not match")
    checks["ARV006"].extend(
        _verify_signature(
            statement,
            receipt.get("observer_signature"),
            observer,
            expected_signer=str(statement.get("observer_id")),
            label=f"{label}.observer_signature",
        )
    )

    observed_root = receipt.get("observed_root")
    root_errors = validate_trust_root(observed_root)
    checks["ARV007"].extend(f"{label}.observed_root: {item}" for item in root_errors)
    if isinstance(observed_root, Mapping):
        if observed_root.get("trust_domain") != policy.get("trust_domain"):
            checks["ARV007"].append(f"{label}.observed_root trust_domain does not match")
        if observed_root.get("root_sha256") != statement.get("observed_root_sha256"):
            checks["ARV007"].append(f"{label}.observed_root digest does not match statement")
        if observed_root.get("version") != statement.get("observed_root_version"):
            checks["ARV007"].append(f"{label}.observed_root version does not match statement")
    if not _is_digest(statement.get("observed_root_sha256")):
        checks["ARV007"].append(f"{label}.statement observed_root_sha256 is invalid")
    if _plain_positive_int(statement.get("observed_root_version")) is None:
        checks["ARV007"].append(f"{label}.statement observed_root_version is invalid")
    return checks


def _classification(
    candidate_digest: Any,
    candidate_version: int | None,
    observed_digest: Any,
    observed_version: int | None,
) -> str:
    if candidate_version is None or observed_version is None:
        return "unclassified"
    if observed_version < candidate_version:
        return "lagging"
    if observed_version > candidate_version:
        return "newer"
    return "matching" if observed_digest == candidate_digest else "same_version_conflict"


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


def _plain_positive_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
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
