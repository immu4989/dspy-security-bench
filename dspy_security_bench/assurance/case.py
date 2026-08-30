"""AssuranceGraph deterministic claim-evidence evaluation.

The evaluator reads only local, bounded JSON artifacts. Each artifact is first
recomputed by its native DSPy Security Bench verifier. AssuranceGraph then
applies frozen, scalar predicates from an owner-selected profile and records
missing, stale, violated, and contradictory evidence without approving a
deployment or accepting risk.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.assurance.profiles import (
    PROFILE_VERSION,
    built_in_profile,
    profile_ids,
)
from dspy_security_bench.continuous.proof import build_evidence_snapshot
from dspy_security_bench.mission.loader import canonical_sha256

CASE_TYPE = "dspy-security-bench-assurance-case"
REPORT_TYPE = "AssuranceGraph / Executable agent assurance case"
PROTOCOL_VERSION = "assurancegraph-v1"
ANALYZER = "deterministic-claim-evidence-graph-v1"
MAX_CASE_BYTES = 1_000_000
MAX_EVIDENCE_BYTES = 50_000_000
MAX_EVIDENCE_ITEMS = 100
CLAIM_STATUSES = (
    "supported",
    "violated",
    "contradicted",
    "stale_evidence",
    "missing_evidence",
)
CLAIM_BOUNDARY = (
    "AssuranceGraph evaluates frozen scalar predicates over locally recomputed evidence within "
    "an owner-declared system boundary and evaluation time. A supported claim means only that "
    "the referenced evidence satisfied the selected profile. It is not proof of system-wide "
    "safety, a certification, compliance determination, risk acceptance, procurement decision, "
    "authorization to operate, or government endorsement. Accountable owners retain every "
    "deployment, monitoring, response, restart, funding, and risk decision."
)
LIMITATIONS = (
    "Only evidence paths declared in the case are evaluated.",
    "A native verifier establishes internal consistency, not the truth of external observations.",
    "Profile predicates are engineering defaults and may omit deployment-specific hazards.",
    "Evidence freshness is computed from owner-supplied observation and evaluation times.",
    "Supported claims do not compose into a universal safety or compliance score.",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CASE_FIELDS = {
    "schema_version",
    "case_type",
    "case_id",
    "title",
    "description",
    "decision_owner",
    "profile_id",
    "evaluation_time",
    "system",
    "evidence",
    "claim_boundary",
    "case_sha256",
}
_SYSTEM_FIELDS = {"system_id", "name", "mission", "environment", "boundary"}
_EVIDENCE_FIELDS = {
    "evidence_id",
    "evidence_kind",
    "path",
    "observed_at",
    "max_age_seconds",
    "owner",
    "expected_sha256",
}


def protocol_payload() -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "profile_version": PROFILE_VERSION,
        "profile_ids": list(profile_ids()),
        "claim_statuses": list(CLAIM_STATUSES),
        "status_semantics": {
            "supported": "current verified evidence satisfies every frozen predicate",
            "violated": "current verified evidence fails one or more frozen predicates",
            "contradicted": "current verified evidence both supports and violates the claim",
            "stale_evidence": "only otherwise-usable evidence beyond its declared age is present",
            "missing_evidence": "no current verified evidence can evaluate the claim",
        },
        "overall_statuses": [
            "profile_evidence_supported",
            "review_required",
            "evidence_contradicts_deployment",
        ],
        "evidence_verification": "native offline semantic verifier before profile predicates",
        "path_policy": "local relative paths confined to an explicit evidence root",
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }


def protocol_sha256() -> str:
    return canonical_sha256(protocol_payload())


def seal_case(case: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _json_clone(case)
    normalized.pop("case_sha256", None)
    normalized["case_sha256"] = canonical_sha256(normalized)
    return normalized


def built_in_case(
    profile_id: str,
    *,
    case_id: str = "example-agent-assurance",
    evaluation_time: int = 1_788_048_000,
) -> dict[str, Any]:
    """Return an editable case whose evidence paths mirror the profile requirements."""

    profile = built_in_profile(profile_id)
    evidence = []
    for claim in profile["claims"]:
        kind = claim["evidence_kind"]
        evidence.append(
            {
                "evidence_id": f"{kind}-evidence",
                "evidence_kind": kind,
                "path": f"evidence/{kind}.json",
                "observed_at": evaluation_time,
                "max_age_seconds": profile["default_max_age_seconds"],
                "owner": "replace-with-accountable-evidence-owner",
                "expected_sha256": "0" * 64,
            }
        )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "case_type": CASE_TYPE,
        "case_id": case_id,
        "title": "Example AI-agent deployment assurance case",
        "description": (
            "Replace the fictional system boundary, accountable owners, evaluation time, and "
            "every evidence artifact before using this as a decision input."
        ),
        "decision_owner": "replace-with-accountable-decision-owner",
        "profile_id": profile_id,
        "evaluation_time": evaluation_time,
        "system": {
            "system_id": "example-agent-system",
            "name": "Example agent system",
            "mission": "Bounded synthetic mission",
            "environment": "synthetic-reference",
            "boundary": "No production system, operational data, or live external effect.",
        },
        "evidence": evidence,
        "claim_boundary": CLAIM_BOUNDARY,
    }
    return seal_case(payload)


def validate_case(case: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(case, Mapping):
        return ("case must be an object",)
    _exact_keys(case, _CASE_FIELDS, "case", errors)
    if case.get("schema_version") != 1 or case.get("case_type") != CASE_TYPE:
        errors.append("case metadata does not match AssuranceGraph v1")
    _identifier(case.get("case_id"), "case_id", errors)
    for field in ("title", "description", "decision_owner"):
        _bounded_string(case.get(field), field, errors, 500)
    if case.get("profile_id") not in profile_ids():
        errors.append("profile_id is not a frozen AssuranceGraph profile")
    evaluation_time = case.get("evaluation_time")
    if isinstance(evaluation_time, bool) or not isinstance(evaluation_time, int):
        errors.append("evaluation_time must be a non-negative integer Unix timestamp")
    elif evaluation_time < 0:
        errors.append("evaluation_time must be a non-negative integer Unix timestamp")
    system = case.get("system")
    if not isinstance(system, Mapping):
        errors.append("system must be an object")
    else:
        _exact_keys(system, _SYSTEM_FIELDS, "system", errors)
        _identifier(system.get("system_id"), "system.system_id", errors)
        for field in ("name", "mission", "environment", "boundary"):
            _bounded_string(system.get(field), f"system.{field}", errors, 1_000)
    evidence = case.get("evidence")
    profile = None
    if case.get("profile_id") in profile_ids():
        profile = built_in_profile(str(case["profile_id"]))
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVIDENCE_ITEMS:
        errors.append(f"evidence must contain 1 to {MAX_EVIDENCE_ITEMS} objects")
        evidence = []
    evidence_ids: set[str] = set()
    for index, item in enumerate(evidence):
        label = f"evidence[{index}]"
        if not isinstance(item, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact_keys(item, _EVIDENCE_FIELDS, label, errors)
        evidence_id = item.get("evidence_id")
        _identifier(evidence_id, f"{label}.evidence_id", errors)
        if isinstance(evidence_id, str) and evidence_id in evidence_ids:
            errors.append(f"duplicate evidence_id {evidence_id!r}")
        elif isinstance(evidence_id, str):
            evidence_ids.add(evidence_id)
        kind = item.get("evidence_kind")
        allowed_kinds = (
            {claim["evidence_kind"] for claim in profile["claims"]} if profile else set()
        )
        if kind not in allowed_kinds:
            errors.append(f"{label}.evidence_kind is not used by the selected profile")
        path = item.get("path")
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 1_000
            or Path(path).is_absolute()
            or ".." in Path(path).parts
        ):
            errors.append(f"{label}.path must be a bounded local relative path")
        observed_at = item.get("observed_at")
        if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
            errors.append(f"{label}.observed_at must be a non-negative integer")
        max_age = item.get("max_age_seconds")
        if (
            isinstance(max_age, bool)
            or not isinstance(max_age, int)
            or not 1 <= max_age <= 31_536_000
        ):
            errors.append(f"{label}.max_age_seconds must be between 1 and 31536000")
        _bounded_string(item.get("owner"), f"{label}.owner", errors, 300)
        digest = item.get("expected_sha256")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            errors.append(f"{label}.expected_sha256 must be a SHA-256 digest")
    if profile:
        present = {item.get("evidence_kind") for item in evidence if isinstance(item, Mapping)}
        required = {claim["evidence_kind"] for claim in profile["claims"]}
        if missing := sorted(required - present):
            errors.append("case omits profile evidence kinds: " + ", ".join(missing))
    if case.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("case claim_boundary does not match AssuranceGraph v1")
    claimed = case.get("case_sha256")
    unsigned = dict(case)
    unsigned.pop("case_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("case_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("case is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def analyze_case(case: Mapping[str, Any], evidence_root: str | Path) -> dict[str, Any]:
    """Verify referenced evidence and evaluate every frozen profile claim."""

    normalized = _json_clone(case)
    errors = validate_case(normalized)
    if errors:
        raise ValueError("invalid AssuranceGraph case: " + "; ".join(errors))
    root = Path(evidence_root).resolve()
    profile = built_in_profile(normalized["profile_id"])
    internal_results = [
        _evaluate_evidence(item, normalized["evaluation_time"], root)
        for item in normalized["evidence"]
    ]
    claim_results = [_evaluate_claim(claim, internal_results) for claim in profile["claims"]]
    status_counts = {
        status: sum(result["status"] == status for result in claim_results)
        for status in CLAIM_STATUSES
    }
    if status_counts["violated"] or status_counts["contradicted"]:
        overall = "evidence_contradicts_deployment"
    elif status_counts["stale_evidence"] or status_counts["missing_evidence"]:
        overall = "review_required"
    else:
        overall = "profile_evidence_supported"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": protocol_sha256(),
        "analyzer": ANALYZER,
        "case": normalized,
        "case_sha256": normalized["case_sha256"],
        "profile": profile,
        "profile_sha256": profile["profile_sha256"],
        "summary": {
            "status": overall,
            "claim_count": len(claim_results),
            "evidence_count": len(internal_results),
            "verified_current_evidence": sum(
                item["verification_status"] == "verified_current" for item in internal_results
            ),
            "invalid_evidence": sum(
                item["verification_status"] == "invalid" for item in internal_results
            ),
            "missing_evidence_files": sum(
                item["verification_status"] == "missing" for item in internal_results
            ),
            "stale_evidence_files": sum(
                item["verification_status"] == "verified_stale" for item in internal_results
            ),
            "claim_status_counts": status_counts,
            "automatic_deployment_actions": 0,
            "automatic_risk_acceptances": 0,
        },
        "evidence_results": [_public_evidence_result(item) for item in internal_results],
        "claim_results": claim_results,
        "informative_crosswalk": _crosswalk(profile),
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_report(payload: Mapping[str, Any], evidence_root: str | Path) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ("report must be an object",)
    if payload.get("report_type") != REPORT_TYPE:
        errors.append("unsupported AssuranceGraph report type")
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        errors.append("unsupported AssuranceGraph protocol version")
    if payload.get("protocol_sha256") != protocol_sha256():
        errors.append("protocol_sha256 does not match this implementation")
    claimed = payload.get("report_sha256")
    unsigned = dict(payload)
    unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    case = payload.get("case")
    if not isinstance(case, Mapping):
        errors.append("report case must be an object")
        return tuple(dict.fromkeys(errors))
    try:
        expected = analyze_case(case, evidence_root)
    except (OSError, TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if payload != expected:
            errors.append("AssuranceGraph report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _evaluate_evidence(item: Mapping[str, Any], evaluation_time: int, root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "evidence_id": item["evidence_id"],
        "evidence_kind": item["evidence_kind"],
        "path": item["path"],
        "owner": item["owner"],
        "observed_at": item["observed_at"],
        "max_age_seconds": item["max_age_seconds"],
        "age_seconds": evaluation_time - item["observed_at"],
        "expected_sha256": item["expected_sha256"],
        "actual_sha256": None,
        "verification_status": "invalid",
        "errors": [],
        "_payload": None,
    }
    candidate = (root / item["path"]).resolve()
    if candidate != root and root not in candidate.parents:
        result["errors"].append("evidence path escapes the declared root")
        return result
    if not candidate.is_file():
        result["verification_status"] = "missing"
        result["errors"].append("evidence file is missing")
        return result
    try:
        if candidate.stat().st_size > MAX_EVIDENCE_BYTES:
            raise ValueError(f"evidence exceeds {MAX_EVIDENCE_BYTES} bytes")
        payload = json.loads(candidate.read_text())
        if not isinstance(payload, dict):
            raise ValueError("evidence JSON root must be an object")
        snapshot = build_evidence_snapshot(payload, label=item["evidence_id"])
        result["actual_sha256"] = snapshot["evidence_sha256"]
        if snapshot["evidence_kind"] != item["evidence_kind"]:
            raise ValueError(
                f"expected {item['evidence_kind']} evidence, observed {snapshot['evidence_kind']}"
            )
        if item["expected_sha256"] != result["actual_sha256"]:
            raise ValueError("evidence digest does not match expected_sha256")
        if result["age_seconds"] < 0:
            raise ValueError("evidence observed_at is later than case evaluation_time")
        result["verification_status"] = (
            "verified_stale"
            if result["age_seconds"] > item["max_age_seconds"]
            else "verified_current"
        )
        result["_payload"] = payload
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        result["errors"].append(str(exc))
    return result


def _evaluate_claim(claim: Mapping[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    applicable = [item for item in evidence if item["evidence_kind"] == claim["evidence_kind"]]
    supporting: list[str] = []
    violating: list[str] = []
    stale: list[str] = []
    unavailable: list[str] = []
    checks: list[dict[str, Any]] = []
    for item in applicable:
        evidence_id = item["evidence_id"]
        if item["verification_status"] == "verified_stale":
            stale.append(evidence_id)
            continue
        if item["verification_status"] != "verified_current":
            unavailable.append(evidence_id)
            continue
        condition_results = [
            _check_condition(item["_payload"], condition) for condition in claim["conditions"]
        ]
        checks.append({"evidence_id": evidence_id, "conditions": condition_results})
        if all(condition["met"] for condition in condition_results):
            supporting.append(evidence_id)
        else:
            violating.append(evidence_id)
    if supporting and violating:
        status = "contradicted"
    elif violating:
        status = "violated"
    elif supporting:
        status = "supported"
    elif stale:
        status = "stale_evidence"
    else:
        status = "missing_evidence"
    return {
        "claim_id": claim["claim_id"],
        "title": claim["title"],
        "statement": claim["statement"],
        "category": claim["category"],
        "criticality": claim["criticality"],
        "required_evidence_kind": claim["evidence_kind"],
        "status": status,
        "supporting_evidence_ids": supporting,
        "violating_evidence_ids": violating,
        "stale_evidence_ids": stale,
        "unavailable_evidence_ids": unavailable,
        "checks": checks,
        "informative_crosswalk": _json_clone(claim["informative_crosswalk"]),
    }


def _check_condition(payload: Mapping[str, Any], condition: Mapping[str, Any]) -> dict[str, Any]:
    exists, observed = _resolve_pointer(payload, condition["pointer"])
    operator, expected = condition["operator"], condition["expected"]
    if not exists:
        met = False
    elif operator == "eq":
        met = type(observed) is type(expected) and observed == expected
    elif operator == "gte":
        met = (
            isinstance(observed, (int, float))
            and not isinstance(observed, bool)
            and isinstance(expected, (int, float))
            and not isinstance(expected, bool)
            and observed >= expected
        )
    elif operator == "lte":
        met = (
            isinstance(observed, (int, float))
            and not isinstance(observed, bool)
            and isinstance(expected, (int, float))
            and not isinstance(expected, bool)
            and observed <= expected
        )
    else:  # Frozen profiles are validated by source review; fail closed on future operators.
        met = False
    return {
        "pointer": condition["pointer"],
        "operator": operator,
        "expected": expected,
        "observed": observed if exists and _scalar(observed) else None,
        "value_present": exists,
        "met": met,
        "rationale": condition["rationale"],
    }


def _resolve_pointer(payload: Mapping[str, Any], pointer: str) -> tuple[bool, Any]:
    current: Any = payload
    for raw in pointer.removeprefix("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and token in current:
            current = current[token]
        else:
            return False, None
    return True, current


def _public_evidence_result(result: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _json_clone(value) for key, value in result.items() if not key.startswith("_")}


def _crosswalk(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for claim in profile["claims"]:
        for reference in claim["informative_crosswalk"]:
            rows.append(
                {
                    "claim_id": claim["claim_id"],
                    "reference": reference,
                    "mapping_status": "informative-not-determinative",
                }
            )
    return rows


def _exact_keys(
    value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]
) -> None:
    missing, extra = sorted(expected - set(value)), sorted(set(value) - expected)
    if missing:
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra:
        errors.append(f"{label} has unsupported fields: {', '.join(extra)}")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _bounded_string(value: Any, label: str, errors: list[str], maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        errors.append(f"{label} must be a non-empty string of at most {maximum} characters")


def _scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
