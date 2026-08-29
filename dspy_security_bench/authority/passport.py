"""Offline-verifiable identity and delegated-authority passports for AI-agent runs."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256

PASSPORT_TYPE = "dspy-security-bench-agent-identity-passport"
REPORT_TYPE = "dspy-security-bench-agent-identity-passport-verification"
PASSPORT_VERSION = "agent-identity-passport-v1"
TRUST_STATUSES = ("verified", "self_attested", "unverified")
DECISIONS = ("allow", "deny", "review")
EFFECT_STATUSES = ("succeeded", "failed", "unknown")
DISCLAIMER = (
    "An Agent Identity Passport is content-addressed authorization evidence, not an identity "
    "credential, trust anchor, legal identity, compliance certificate, authorization to operate, "
    "or proof that unrecorded effects did not occur. Owners must authenticate issuers, validate "
    "trust roots, protect signing keys, and enforce authorization at the effect boundary."
)

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ROOT_FIELDS = {
    "schema_version",
    "passport_type",
    "passport_version",
    "passport_id",
    "evaluation_time",
    "issued_at",
    "expires_at",
    "principal_id",
    "agent_id",
    "tenant",
    "run_id",
    "task_id",
    "audiences",
    "scopes",
    "delegation_chain",
    "authorization_receipts",
    "effect_receipts",
    "revocations",
    "claim_boundary",
    "passport_sha256",
}
_LINK_FIELDS = {
    "link_id",
    "parent_link_id",
    "delegator_id",
    "delegate_id",
    "audiences",
    "scopes",
    "not_before",
    "expires_at",
    "trust_status",
    "evidence_sha256",
}
_AUTH_FIELDS = {
    "receipt_id",
    "issuer_id",
    "subject_agent_id",
    "run_id",
    "task_id",
    "audience",
    "scope",
    "action",
    "resource_id",
    "decision",
    "issued_at",
    "expires_at",
    "nonce",
    "trust_status",
    "evidence_sha256",
}
_EFFECT_FIELDS = {
    "effect_id",
    "agent_id",
    "run_id",
    "task_id",
    "audience",
    "scope",
    "action",
    "resource_id",
    "executed_at",
    "authorization_receipt_id",
    "status",
    "evidence_sha256",
}
_REVOCATION_FIELDS = {
    "revocation_id",
    "target_type",
    "target_id",
    "issuer_id",
    "issued_at",
    "trust_status",
    "evidence_sha256",
}


def protocol_payload() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "passport_version": PASSPORT_VERSION,
        "trust_statuses": list(TRUST_STATUSES),
        "decisions": list(DECISIONS),
        "binding_dimensions": [
            "principal",
            "agent",
            "tenant",
            "run",
            "task",
            "audience",
            "scope",
            "action",
            "resource",
            "time",
            "nonce",
        ],
        "rules": {
            "IP001": "Passport or effect identity binding mismatch",
            "IP002": "Delegation chain is broken, expired, or escalates authority",
            "IP003": "Authorization receipt is denied, expired, or incorrectly bound",
            "IP004": "Authority was revoked before an effect",
            "IP005": "Effect lacks a matching prior authorization receipt",
            "IP006": "Authority evidence lacks verified trust status",
            "IP007": "Authorization nonce or effect identifier is replayed",
        },
        "claim_boundary": DISCLAIMER,
    }


def protocol_sha256() -> str:
    return canonical_sha256(protocol_payload())


def validate_passport(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if set(payload) != _ROOT_FIELDS:
        errors.append("passport fields are incomplete or unsupported")
    if (
        payload.get("schema_version") != 1
        or payload.get("passport_type") != PASSPORT_TYPE
        or payload.get("passport_version") != PASSPORT_VERSION
    ):
        errors.append("passport metadata is unsupported")
    for field in (
        "passport_id",
        "principal_id",
        "agent_id",
        "tenant",
        "run_id",
        "task_id",
    ):
        _safe(payload.get(field), field, errors)
    for field in ("evaluation_time", "issued_at", "expires_at"):
        _timestamp(payload.get(field), field, errors)
    if _is_int(payload.get("issued_at")) and _is_int(payload.get("expires_at")):
        if payload["issued_at"] >= payload["expires_at"]:
            errors.append("passport expires_at must be after issued_at")
    for field in ("audiences", "scopes"):
        _safe_list(payload.get(field), field, errors, non_empty=True)
    if payload.get("claim_boundary") != DISCLAIMER:
        errors.append("claim_boundary does not match the passport protocol")

    links = _objects(payload.get("delegation_chain"), "delegation_chain", 1, 32, errors)
    link_ids: set[str] = set()
    for index, link in enumerate(links):
        label = f"delegation_chain[{index}]"
        if set(link) != _LINK_FIELDS:
            errors.append(f"{label} fields are incomplete or unsupported")
        for field in ("link_id", "delegator_id", "delegate_id"):
            _safe(link.get(field), f"{label}.{field}", errors)
        parent = link.get("parent_link_id")
        if parent is not None:
            _safe(parent, f"{label}.parent_link_id", errors)
        _safe_list(link.get("audiences"), f"{label}.audiences", errors, non_empty=True)
        _safe_list(link.get("scopes"), f"{label}.scopes", errors, non_empty=True)
        for field in ("not_before", "expires_at"):
            _timestamp(link.get(field), f"{label}.{field}", errors)
        _trust_and_digest(link, label, errors)
        link_id = link.get("link_id")
        if isinstance(link_id, str):
            if link_id in link_ids:
                errors.append(f"duplicate delegation link {link_id!r}")
            link_ids.add(link_id)

    receipts = _objects(
        payload.get("authorization_receipts"), "authorization_receipts", 0, 1000, errors
    )
    receipt_ids: set[str] = set()
    for index, receipt in enumerate(receipts):
        label = f"authorization_receipts[{index}]"
        if set(receipt) != _AUTH_FIELDS:
            errors.append(f"{label} fields are incomplete or unsupported")
        for field in (
            "receipt_id",
            "issuer_id",
            "subject_agent_id",
            "run_id",
            "task_id",
            "audience",
            "scope",
            "action",
            "resource_id",
            "nonce",
        ):
            _safe(receipt.get(field), f"{label}.{field}", errors)
        if receipt.get("decision") not in DECISIONS:
            errors.append(f"{label}.decision is unsupported")
        for field in ("issued_at", "expires_at"):
            _timestamp(receipt.get(field), f"{label}.{field}", errors)
        _trust_and_digest(receipt, label, errors)
        receipt_id = receipt.get("receipt_id")
        if isinstance(receipt_id, str):
            if receipt_id in receipt_ids:
                errors.append(f"duplicate authorization receipt {receipt_id!r}")
            receipt_ids.add(receipt_id)

    effects = _objects(payload.get("effect_receipts"), "effect_receipts", 0, 1000, errors)
    effect_ids: set[str] = set()
    for index, effect in enumerate(effects):
        label = f"effect_receipts[{index}]"
        if set(effect) != _EFFECT_FIELDS:
            errors.append(f"{label} fields are incomplete or unsupported")
        for field in (
            "effect_id",
            "agent_id",
            "run_id",
            "task_id",
            "audience",
            "scope",
            "action",
            "resource_id",
            "authorization_receipt_id",
        ):
            _safe(effect.get(field), f"{label}.{field}", errors)
        _timestamp(effect.get("executed_at"), f"{label}.executed_at", errors)
        if effect.get("status") not in EFFECT_STATUSES:
            errors.append(f"{label}.status is unsupported")
        _digest(effect.get("evidence_sha256"), f"{label}.evidence_sha256", errors)
        effect_id = effect.get("effect_id")
        if isinstance(effect_id, str):
            if effect_id in effect_ids:
                errors.append(f"duplicate effect receipt {effect_id!r}")
            effect_ids.add(effect_id)

    revocations = _objects(payload.get("revocations"), "revocations", 0, 1000, errors)
    revocation_ids: set[str] = set()
    for index, revocation in enumerate(revocations):
        label = f"revocations[{index}]"
        if set(revocation) != _REVOCATION_FIELDS:
            errors.append(f"{label} fields are incomplete or unsupported")
        for field in ("revocation_id", "target_id", "issuer_id"):
            _safe(revocation.get(field), f"{label}.{field}", errors)
        if revocation.get("target_type") not in {
            "passport",
            "agent",
            "delegation_link",
            "authorization_receipt",
        }:
            errors.append(f"{label}.target_type is unsupported")
        _timestamp(revocation.get("issued_at"), f"{label}.issued_at", errors)
        _trust_and_digest(revocation, label, errors)
        revocation_id = revocation.get("revocation_id")
        if isinstance(revocation_id, str):
            if revocation_id in revocation_ids:
                errors.append(f"duplicate revocation {revocation_id!r}")
            revocation_ids.add(revocation_id)

    unsigned = dict(payload)
    claimed = unsigned.pop("passport_sha256", None)
    try:
        if not isinstance(claimed, str) or claimed != canonical_sha256(unsigned):
            errors.append("passport_sha256 does not match canonical passport content")
    except (TypeError, ValueError):
        errors.append("passport must contain canonical JSON data")
    return tuple(dict.fromkeys(errors))


def analyze_passport(payload: Mapping[str, Any]) -> dict[str, Any]:
    errors = validate_passport(payload)
    if errors:
        raise ValueError("invalid Agent Identity Passport: " + "; ".join(errors))
    passport = deepcopy(dict(payload))
    findings: list[dict[str, Any]] = []
    now = passport["evaluation_time"]

    if not passport["issued_at"] <= now < passport["expires_at"]:
        findings.append(_finding("IP001", "passport", passport["passport_id"]))

    parent: Mapping[str, Any] | None = None
    for index, link in enumerate(passport["delegation_chain"]):
        broken = False
        if index == 0:
            broken = (
                link["delegator_id"] != passport["principal_id"]
                or link["parent_link_id"] is not None
            )
        else:
            assert parent is not None
            broken = (
                link["parent_link_id"] != parent["link_id"]
                or link["delegator_id"] != parent["delegate_id"]
                or not set(link["scopes"]).issubset(parent["scopes"])
                or not set(link["audiences"]).issubset(parent["audiences"])
                or link["expires_at"] > parent["expires_at"]
            )
        broken = broken or not link["not_before"] <= now < link["expires_at"]
        broken = broken or not set(link["scopes"]).issubset(passport["scopes"])
        broken = broken or not set(link["audiences"]).issubset(passport["audiences"])
        if broken:
            findings.append(_finding("IP002", "delegation_link", link["link_id"]))
        if link["trust_status"] != "verified":
            findings.append(_finding("IP006", "delegation_link", link["link_id"]))
        parent = link
    if parent is None or parent["delegate_id"] != passport["agent_id"]:
        findings.append(_finding("IP001", "agent", passport["agent_id"]))

    revocations = passport["revocations"]
    for revocation in revocations:
        if revocation["trust_status"] != "verified":
            findings.append(_finding("IP006", "revocation", revocation["revocation_id"]))

    receipt_by_id = {item["receipt_id"]: item for item in passport["authorization_receipts"]}
    nonces = Counter(item["nonce"] for item in passport["authorization_receipts"])
    for receipt in passport["authorization_receipts"]:
        binding_ok = (
            receipt["subject_agent_id"] == passport["agent_id"]
            and receipt["run_id"] == passport["run_id"]
            and receipt["task_id"] == passport["task_id"]
            and receipt["audience"] in passport["audiences"]
            and receipt["scope"] in passport["scopes"]
            and receipt["decision"] == "allow"
            and receipt["issued_at"] <= now < receipt["expires_at"]
        )
        if not binding_ok:
            findings.append(_finding("IP003", "authorization_receipt", receipt["receipt_id"]))
        if receipt["trust_status"] != "verified":
            findings.append(_finding("IP006", "authorization_receipt", receipt["receipt_id"]))
        if nonces[receipt["nonce"]] > 1:
            findings.append(_finding("IP007", "authorization_receipt", receipt["receipt_id"]))

    for effect in passport["effect_receipts"]:
        receipt = receipt_by_id.get(effect["authorization_receipt_id"])
        match = bool(
            receipt
            and receipt["decision"] == "allow"
            and receipt["subject_agent_id"] == effect["agent_id"] == passport["agent_id"]
            and receipt["run_id"] == effect["run_id"] == passport["run_id"]
            and receipt["task_id"] == effect["task_id"] == passport["task_id"]
            and receipt["audience"] == effect["audience"]
            and receipt["scope"] == effect["scope"]
            and receipt["action"] == effect["action"]
            and receipt["resource_id"] == effect["resource_id"]
            and receipt["issued_at"] <= effect["executed_at"] < receipt["expires_at"]
        )
        if not match:
            findings.append(_finding("IP005", "effect", effect["effect_id"]))
        targets = {
            ("passport", passport["passport_id"]),
            ("agent", passport["agent_id"]),
            ("authorization_receipt", effect["authorization_receipt_id"]),
            *(("delegation_link", link["link_id"]) for link in passport["delegation_chain"]),
        }
        if any(
            (revocation["target_type"], revocation["target_id"]) in targets
            and revocation["issued_at"] <= effect["executed_at"]
            and revocation["trust_status"] == "verified"
            for revocation in revocations
        ):
            findings.append(_finding("IP004", "effect", effect["effect_id"]))

    findings = sorted(
        {canonical_sha256(item): item for item in findings}.values(),
        key=lambda item: (item["rule_id"], item["subject_type"], item["subject_id"]),
    )
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "passport_version": PASSPORT_VERSION,
        "protocol_sha256": protocol_sha256(),
        "passport_sha256": passport["passport_sha256"],
        "passport": passport,
        "summary": {
            "status": "verified" if not findings else "review_required",
            "finding_count": len(findings),
            "delegation_depth": len(passport["delegation_chain"]),
            "authorization_receipt_count": len(passport["authorization_receipts"]),
            "effect_receipt_count": len(passport["effect_receipts"]),
            "revocation_count": len(passport["revocations"]),
            "all_authority_trust_verified": all(
                item["trust_status"] == "verified"
                for item in (
                    passport["delegation_chain"]
                    + passport["authorization_receipts"]
                    + passport["revocations"]
                )
            ),
        },
        "findings": findings,
        "claim_boundary": DISCLAIMER,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_report(payload: Mapping[str, Any]) -> tuple[str, ...]:
    fields = {
        "schema_version",
        "report_type",
        "passport_version",
        "protocol_sha256",
        "passport_sha256",
        "passport",
        "summary",
        "findings",
        "claim_boundary",
        "report_sha256",
    }
    errors: list[str] = []
    if set(payload) != fields:
        errors.append("passport report fields are incomplete or unsupported")
    passport = payload.get("passport")
    if not isinstance(passport, Mapping):
        return ("passport must be an object",)
    passport_errors = validate_passport(passport)
    errors.extend(f"passport: {item}" for item in passport_errors)
    unsigned = dict(payload)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not match canonical report content")
    except (TypeError, ValueError):
        errors.append("report must contain canonical JSON data")
    if passport_errors:
        return tuple(dict.fromkeys(errors))
    expected = analyze_passport(passport)
    for field in sorted(fields - {"report_sha256"}):
        if payload.get(field) != expected.get(field):
            errors.append(f"{field} does not recompute")
    return tuple(dict.fromkeys(errors))


def built_in_passport(profile: str = "bounded") -> dict[str, Any]:
    if profile not in {"bounded", "revoked", "ambient"}:
        raise ValueError(f"unknown passport profile {profile!r}")
    now = 1_767_225_600
    link = {
        "link_id": "delegation-1",
        "parent_link_id": None,
        "delegator_id": "human-alice",
        "delegate_id": "agent-orchestrator",
        "audiences": ["mcp://records"],
        "scopes": ["records:read"],
        "not_before": now - 60,
        "expires_at": now + 3600,
        "trust_status": "verified" if profile != "ambient" else "self_attested",
        "evidence_sha256": canonical_sha256({"fixture": profile, "kind": "delegation"}),
    }
    auth = {
        "receipt_id": "authorization-1",
        "issuer_id": "policy-engine",
        "subject_agent_id": "agent-orchestrator",
        "run_id": "run-1",
        "task_id": "task-1",
        "audience": "mcp://records",
        "scope": "records:read",
        "action": "records.read",
        "resource_id": "record-1",
        "decision": "allow",
        "issued_at": now - 10,
        "expires_at": now + 300,
        "nonce": "nonce-1",
        "trust_status": "verified" if profile != "ambient" else "unverified",
        "evidence_sha256": canonical_sha256({"fixture": profile, "kind": "authorization"}),
    }
    effect = {
        "effect_id": "effect-1",
        "agent_id": "agent-orchestrator",
        "run_id": "run-1",
        "task_id": "task-1",
        "audience": "mcp://records",
        "scope": "records:read",
        "action": "records.read",
        "resource_id": "record-1",
        "executed_at": now,
        "authorization_receipt_id": "authorization-1",
        "status": "succeeded",
        "evidence_sha256": canonical_sha256({"fixture": profile, "kind": "effect"}),
    }
    revocations = []
    if profile == "revoked":
        revocations.append(
            {
                "revocation_id": "revocation-1",
                "target_type": "authorization_receipt",
                "target_id": "authorization-1",
                "issuer_id": "policy-engine",
                "issued_at": now - 1,
                "trust_status": "verified",
                "evidence_sha256": canonical_sha256({"fixture": profile, "kind": "revocation"}),
            }
        )
    passport: dict[str, Any] = {
        "schema_version": 1,
        "passport_type": PASSPORT_TYPE,
        "passport_version": PASSPORT_VERSION,
        "passport_id": f"passport-{profile}",
        "evaluation_time": now,
        "issued_at": now - 60,
        "expires_at": now + 3600,
        "principal_id": "human-alice",
        "agent_id": "agent-orchestrator",
        "tenant": "tenant-north",
        "run_id": "run-1",
        "task_id": "task-1",
        "audiences": ["mcp://records"],
        "scopes": ["records:read"],
        "delegation_chain": [link],
        "authorization_receipts": [auth],
        "effect_receipts": [effect],
        "revocations": revocations,
        "claim_boundary": DISCLAIMER,
    }
    passport["passport_sha256"] = canonical_sha256(passport)
    return passport


def _finding(rule_id: str, subject_type: str, subject_id: str) -> dict[str, str]:
    messages = {
        "IP001": "Identity or passport lifetime does not match the claimed run.",
        "IP002": "Delegation chain is broken, expired, or increases authority.",
        "IP003": "Authorization receipt is not an active, correctly bound allow decision.",
        "IP004": "Verified revocation predates this effect.",
        "IP005": "Effect lacks an exactly matching prior authorization receipt.",
        "IP006": "Authority evidence is not backed by a verified trust status.",
        "IP007": "Authorization nonce or effect identifier was replayed.",
    }
    return {
        "rule_id": rule_id,
        "severity": "critical" if rule_id in {"IP004", "IP005", "IP007"} else "high",
        "subject_type": subject_type,
        "subject_id": subject_id,
        "message": messages[rule_id],
    }


def _objects(
    value: Any, label: str, minimum: int, maximum: int, errors: list[str]
) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        errors.append(f"{label} must contain between {minimum} and {maximum} objects")
        return []
    if any(not isinstance(item, Mapping) for item in value):
        errors.append(f"{label} must contain only objects")
        return []
    return value


def _safe(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _SAFE.fullmatch(value):
        errors.append(f"{label} must be a safe identifier")


def _safe_list(value: Any, label: str, errors: list[str], *, non_empty: bool) -> None:
    if not isinstance(value, list) or (non_empty and not value):
        errors.append(f"{label} must be a{' non-empty' if non_empty else ''} list")
    elif (
        any(not isinstance(item, str) or not _SAFE.fullmatch(item) for item in value)
        or len(value) != len(set(value))
        or value != sorted(value)
    ):
        errors.append(f"{label} must contain sorted, unique safe identifiers")


def _timestamp(value: Any, label: str, errors: list[str]) -> None:
    if not _is_int(value) or value < 0:
        errors.append(f"{label} must be a non-negative integer Unix timestamp")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _digest(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        errors.append(f"{label} must be a lowercase SHA-256 digest")


def _trust_and_digest(item: Mapping[str, Any], label: str, errors: list[str]) -> None:
    if item.get("trust_status") not in TRUST_STATUSES:
        errors.append(f"{label}.trust_status is unsupported")
    _digest(item.get("evidence_sha256"), f"{label}.evidence_sha256", errors)
