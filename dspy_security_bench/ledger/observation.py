"""Signed, privacy-bounded observer receipts for independently exchanged checkpoints."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.proof import (
    _sign_payload,
    _validate_key,
    _verify_signature,
    validate_policy,
    verify_checkpoint_signature_bundle,
    verify_ledger_report,
)
from dspy_security_bench.mission.loader import canonical_sha256

POLICY_TYPE = "dspy-security-bench-assurance-ledger-observer-policy"
REPORT_TYPE = "AssuranceLedger ObserverReceipt / Independent checkpoint observation evidence"
PROTOCOL_VERSION = "assuranceledger-observer-receipt-v1"
ANALYZER = "deterministic-observer-independence-analyzer-v1"
CHANNEL_CLASSES = (
    "offline-transfer",
    "separately-administered-api",
    "transparency-distributor",
    "witness-feed",
)
MAX_OBSERVERS = 50
MAX_RECEIPTS = 50
CLAIM_BOUNDARY = (
    "AssuranceLedger ObserverReceipt verifies policy-authorized Ed25519 observer signatures, "
    "the exact signed checkpoints each observer says it received, bounded observation delay, "
    "and declared organization/channel separation. A satisfied observation quorum makes "
    "cross-source provenance inspectable and can evidence a same-size checkpoint conflict. "
    "It does not prove observer identity, independence, channel confidentiality, report "
    "possession beyond the signed declaration, event truth, global consistency, model safety, "
    "compliance, authorization to operate, deployment authority, or risk acceptance."
)
LIMITATIONS = (
    "Observer, organization, and channel-class identifiers are owner-governed policy assertions, not externally proofed identities.",
    "Only a SHA-256 digest of the channel locator is disclosed; channel control and confidentiality remain deployment responsibilities.",
    "A receipt proves a key signed an observation statement, not that its organization is operationally independent.",
    "The analyzer takes no notification, remediation, deployment, authorization, or risk-acceptance action.",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_FIELDS = {
    "schema_version",
    "policy_type",
    "exchange_id",
    "observers",
    "minimum_observers",
    "minimum_distinct_organizations",
    "minimum_distinct_channels",
    "maximum_observation_delay_seconds",
    "allowed_channel_classes",
    "claim_boundary",
    "policy_sha256",
}
_RECEIPT_FIELDS = {"statement", "signed_checkpoint", "observer_signature"}
_STATEMENT_FIELDS = {
    "protocol_version",
    "observer_policy_sha256",
    "ledger_policy_sha256",
    "observer_id",
    "observer_organization_id",
    "channel_class",
    "channel_locator_sha256",
    "observed_at",
    "source_ledger_report_sha256",
    "signed_checkpoint_sha256",
}


def build_observer_policy(
    observers: Sequence[Mapping[str, Any]],
    *,
    exchange_id: str,
    minimum_observers: int,
    minimum_distinct_organizations: int,
    minimum_distinct_channels: int,
    maximum_observation_delay_seconds: int,
    allowed_channel_classes: Sequence[str] = CHANNEL_CLASSES,
) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "schema_version": 1,
        "policy_type": POLICY_TYPE,
        "exchange_id": exchange_id,
        "observers": sorted(
            (deepcopy(dict(item)) for item in observers), key=lambda item: item["entity_id"]
        ),
        "minimum_observers": minimum_observers,
        "minimum_distinct_organizations": minimum_distinct_organizations,
        "minimum_distinct_channels": minimum_distinct_channels,
        "maximum_observation_delay_seconds": maximum_observation_delay_seconds,
        "allowed_channel_classes": sorted(set(allowed_channel_classes)),
        "claim_boundary": CLAIM_BOUNDARY,
    }
    policy["policy_sha256"] = canonical_sha256(policy)
    if errors := validate_observer_policy(policy):
        raise ValueError("invalid observer policy: " + "; ".join(errors))
    return policy


def validate_observer_policy(policy: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(policy, Mapping):
        return ("observer policy must be an object",)
    _exact(policy, _POLICY_FIELDS, "observer policy", errors)
    if policy.get("schema_version") != 1 or policy.get("policy_type") != POLICY_TYPE:
        errors.append("observer policy metadata does not match v1")
    _identifier(policy.get("exchange_id"), "exchange_id", errors)
    observers = policy.get("observers")
    if not isinstance(observers, list) or not 2 <= len(observers) <= MAX_OBSERVERS:
        errors.append(f"observers must contain 2 to {MAX_OBSERVERS} entries")
        observers = []
    ids: set[str] = set()
    organizations: set[str] = set()
    for index, observer in enumerate(observers):
        item = _validate_key(observer, f"observers[{index}]", errors)
        if item is None:
            continue
        if item.get("entity_id") in ids:
            errors.append(f"duplicate observer entity_id {item.get('entity_id')!r}")
        ids.add(str(item.get("entity_id")))
        organizations.add(str(item.get("organization_id")))
    allowed = policy.get("allowed_channel_classes")
    if (
        not isinstance(allowed, list)
        or not allowed
        or allowed != sorted(set(allowed))
        or any(item not in CHANNEL_CLASSES for item in allowed)
    ):
        errors.append("allowed_channel_classes must be a sorted non-empty supported set")
        allowed = []
    minimum = _nonnegative_int(policy.get("minimum_observers"), "minimum_observers", errors)
    org_minimum = _nonnegative_int(
        policy.get("minimum_distinct_organizations"),
        "minimum_distinct_organizations",
        errors,
    )
    channel_minimum = _nonnegative_int(
        policy.get("minimum_distinct_channels"), "minimum_distinct_channels", errors
    )
    delay = _nonnegative_int(
        policy.get("maximum_observation_delay_seconds"),
        "maximum_observation_delay_seconds",
        errors,
    )
    if minimum is not None and not 2 <= minimum <= len(observers):
        errors.append("minimum_observers is outside the observer bound")
    if org_minimum is not None and not 2 <= org_minimum <= len(organizations):
        errors.append("minimum_distinct_organizations cannot be met")
    if channel_minimum is not None and not 2 <= channel_minimum <= len(allowed):
        errors.append("minimum_distinct_channels cannot be met")
    if delay is not None and delay < 1:
        errors.append("maximum_observation_delay_seconds must be positive")
    if policy.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match ObserverReceipt v1")
    unsigned = dict(policy)
    claimed = unsigned.pop("policy_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("observer policy_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("observer policy is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def create_observer_receipt(
    observer_policy: Mapping[str, Any],
    ledger_report: Mapping[str, Any],
    private_key_path: str | Path,
    *,
    observer_id: str,
    channel_class: str,
    channel_locator: str,
    observed_at: int,
    evidence_root: str | Path,
) -> dict[str, Any]:
    if errors := validate_observer_policy(observer_policy):
        raise ValueError("invalid observer policy: " + "; ".join(errors))
    if errors := verify_ledger_report(ledger_report, evidence_root=evidence_root):
        raise ValueError("invalid ledger report: " + "; ".join(errors))
    observer_map = {item["entity_id"]: item for item in observer_policy["observers"]}
    observer = observer_map.get(observer_id)
    if observer is None:
        raise ValueError("observer_id is not authorized by the observer policy")
    if channel_class not in observer_policy["allowed_channel_classes"]:
        raise ValueError("channel_class is not allowed by the observer policy")
    if not isinstance(channel_locator, str) or not channel_locator.strip():
        raise ValueError("channel_locator must be a non-empty private input")
    checkpoint = ledger_report["checkpoint"]
    statement = {
        "protocol_version": PROTOCOL_VERSION,
        "observer_policy_sha256": observer_policy["policy_sha256"],
        "ledger_policy_sha256": ledger_report["policy"]["policy_sha256"],
        "observer_id": observer_id,
        "observer_organization_id": observer["organization_id"],
        "channel_class": channel_class,
        "channel_locator_sha256": hashlib.sha256(channel_locator.encode()).hexdigest(),
        "observed_at": observed_at,
        "source_ledger_report_sha256": ledger_report["report_sha256"],
        "signed_checkpoint_sha256": canonical_sha256(checkpoint),
    }
    receipt = {
        "statement": statement,
        "signed_checkpoint": deepcopy(checkpoint),
        "observer_signature": _sign_payload(
            statement,
            private_key_path,
            observer,
            signer_id=observer_id,
        ),
    }
    errors = _verify_receipt(observer_policy, ledger_report["policy"], receipt, 0)
    if errors:
        raise ValueError("generated observer receipt is invalid: " + "; ".join(errors))
    return receipt


def analyze_observer_receipts(
    observer_policy: Mapping[str, Any],
    ledger_policy: Mapping[str, Any],
    receipts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    source_errors = [*validate_observer_policy(observer_policy), *validate_policy(ledger_policy)]
    if not isinstance(receipts, list) or not 2 <= len(receipts) <= MAX_RECEIPTS:
        raise ValueError(f"receipts must contain 2 to {MAX_RECEIPTS} entries")
    results = []
    valid = []
    for index, receipt in enumerate(receipts):
        errors = _verify_receipt(observer_policy, ledger_policy, receipt, index)
        statement = receipt.get("statement", {}) if isinstance(receipt, Mapping) else {}
        checkpoint = (
            receipt.get("signed_checkpoint", {}).get("checkpoint", {})
            if isinstance(receipt, Mapping)
            else {}
        )
        results.append(
            {
                "receipt_index": index,
                "observer_id": statement.get("observer_id"),
                "observer_organization_id": statement.get("observer_organization_id"),
                "channel_class": statement.get("channel_class"),
                "channel_locator_sha256": statement.get("channel_locator_sha256"),
                "tree_size": checkpoint.get("tree_size"),
                "root_sha256": checkpoint.get("root_sha256"),
                "status": "valid" if not errors else "invalid",
                "errors": list(errors),
            }
        )
        if not errors:
            valid.append(receipt)
    observer_ids = [item["statement"]["observer_id"] for item in valid]
    organizations = {item["statement"]["observer_organization_id"] for item in valid}
    channels = {item["statement"]["channel_locator_sha256"] for item in valid}
    checkpoints = {
        canonical_sha256(item["signed_checkpoint"]): item["signed_checkpoint"] for item in valid
    }
    fork_pairs = 0
    values = list(checkpoints.values())
    for left_index, left in enumerate(values):
        for right in values[left_index + 1 :]:
            first = left["checkpoint"]
            second = right["checkpoint"]
            fork_pairs += (
                first["tree_size"] == second["tree_size"]
                and first["root_sha256"] != second["root_sha256"]
            )
    independent = (
        len(valid) >= observer_policy.get("minimum_observers", MAX_RECEIPTS + 1)
        and len(set(observer_ids)) == len(observer_ids)
        and len(organizations)
        >= observer_policy.get("minimum_distinct_organizations", MAX_RECEIPTS + 1)
        and len(channels) >= observer_policy.get("minimum_distinct_channels", MAX_RECEIPTS + 1)
    )
    if source_errors or len(valid) != len(receipts):
        status = "invalid_observation_evidence"
    elif not independent:
        status = "insufficient_observer_independence"
    elif fork_pairs:
        status = "independently_observed_equivocation"
    elif len(checkpoints) == 1:
        status = "checkpoint_corroborated"
    else:
        status = "independent_checkpoint_observations"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "observer_policy": deepcopy(dict(observer_policy)),
        "ledger_policy": deepcopy(dict(ledger_policy)),
        "receipts": deepcopy(list(receipts)),
        "source_errors": list(source_errors),
        "receipt_results": results,
        "summary": {
            "status": status,
            "submitted_receipts": len(receipts),
            "valid_receipts": len(valid),
            "distinct_observers": len(set(observer_ids)),
            "distinct_organizations": len(organizations),
            "distinct_channels": len(channels),
            "distinct_checkpoints": len(checkpoints),
            "same_size_fork_pairs": fork_pairs,
            "embedded_log_entries": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_observer_report(report: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger ObserverReceipt report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = analyze_observer_receipts(
            report.get("observer_policy", {}),
            report.get("ledger_policy", {}),
            report.get("receipts", []),
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("ObserverReceipt report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _verify_receipt(
    observer_policy: Mapping[str, Any],
    ledger_policy: Mapping[str, Any],
    receipt: Any,
    index: int,
) -> tuple[str, ...]:
    errors: list[str] = []
    label = f"receipts[{index}]"
    if not isinstance(receipt, Mapping):
        return (f"{label} must be an object",)
    _exact(receipt, _RECEIPT_FIELDS, label, errors)
    statement = receipt.get("statement")
    if not isinstance(statement, Mapping):
        return tuple([*errors, f"{label}.statement must be an object"])
    _exact(statement, _STATEMENT_FIELDS, f"{label}.statement", errors)
    if statement.get("protocol_version") != PROTOCOL_VERSION:
        errors.append(f"{label}.statement protocol_version is invalid")
    if statement.get("observer_policy_sha256") != observer_policy.get("policy_sha256"):
        errors.append(f"{label}.statement observer policy does not match")
    if statement.get("ledger_policy_sha256") != ledger_policy.get("policy_sha256"):
        errors.append(f"{label}.statement ledger policy does not match")
    observer_map = {
        item["entity_id"]: item
        for item in observer_policy.get("observers", [])
        if isinstance(item, Mapping) and "entity_id" in item
    }
    observer = observer_map.get(statement.get("observer_id"))
    if observer is None:
        errors.append(f"{label}.statement observer is not policy-authorized")
        observer = {}
    elif statement.get("observer_organization_id") != observer.get("organization_id"):
        errors.append(f"{label}.statement observer organization does not match policy")
    if statement.get("channel_class") not in observer_policy.get("allowed_channel_classes", []):
        errors.append(f"{label}.statement channel_class is not allowed")
    _digest(statement.get("channel_locator_sha256"), f"{label}.channel locator", errors)
    _digest(statement.get("source_ledger_report_sha256"), f"{label}.source report", errors)
    checkpoint = receipt.get("signed_checkpoint")
    if not isinstance(checkpoint, Mapping):
        errors.append(f"{label}.signed_checkpoint must be an object")
        checkpoint = {}
    else:
        errors.extend(
            f"{label}: {item}"
            for item in verify_checkpoint_signature_bundle(ledger_policy, checkpoint)
        )
    try:
        if statement.get("signed_checkpoint_sha256") != canonical_sha256(checkpoint):
            errors.append(f"{label}.statement checkpoint digest does not match")
    except (TypeError, ValueError):
        errors.append(f"{label}.signed_checkpoint is not canonical JSON data")
    observed_at = _nonnegative_int(
        statement.get("observed_at"), f"{label}.statement.observed_at", errors
    )
    issued_at = checkpoint.get("checkpoint", {}).get("issued_at")
    if observed_at is not None and isinstance(issued_at, int):
        delay = observed_at - issued_at
        if delay < 0:
            errors.append(f"{label}.statement observation predates checkpoint issuance")
        elif delay > observer_policy.get("maximum_observation_delay_seconds", -1):
            errors.append(f"{label}.statement observation exceeds the policy delay")
    errors.extend(
        _verify_signature(
            statement,
            receipt.get("observer_signature"),
            observer,
            expected_signer=str(statement.get("observer_id")),
            label=f"{label}.observer_signature",
        )
    )
    return tuple(dict.fromkeys(errors))


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    if missing := sorted(expected - set(value)):
        errors.append(f"{label} is missing fields: {', '.join(missing)}")
    if extra := sorted(set(value) - expected):
        errors.append(f"{label} has unexpected fields: {', '.join(extra)}")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _digest(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        errors.append(f"{label} must be a lowercase SHA-256 digest")


def _nonnegative_int(value: Any, label: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        errors.append(f"{label} must be a non-negative integer")
        return None
    return value
