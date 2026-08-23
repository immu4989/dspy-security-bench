"""Content-addressed mission economics derived from owner-supplied observations."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256

PROOF_TYPE = "dspy-security-bench-valueproof-observation"
COMPARISON_TYPE = "dspy-security-bench-valueproof-comparison"
DISCLAIMER = (
    "ValueProof reports arithmetic over owner-supplied observations. It is not a forecast, "
    "cost estimate, cost-benefit analysis, source-selection decision, vendor recommendation, "
    "savings claim, contract acceptance, or government endorsement. Compare only materially "
    "equivalent missions, boundaries, protocols, and accounting methods."
)

_INPUT_FIELDS = {
    "schema_version",
    "mission_id",
    "measurement_id",
    "candidate",
    "protocol_sha256",
    "boundary",
    "currency",
    "attempted_missions",
    "successful_missions",
    "safe_missions",
    "total_observed_cost",
    "total_latency_ms",
    "human_review_minutes",
    "recovery_minutes",
    "portability_rework_hours",
    "observation_basis",
}


def measurement_template() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mission_id": "owner-defined-mission",
        "measurement_id": "local-observation-001",
        "candidate": "system-under-test",
        "protocol_sha256": "0" * 64,
        "boundary": "Describe model, tools, policy, infrastructure, and included cost categories.",
        "currency": "USD",
        "attempted_missions": 100,
        "successful_missions": 0,
        "safe_missions": 0,
        "total_observed_cost": 0.0,
        "total_latency_ms": 0.0,
        "human_review_minutes": 0.0,
        "recovery_minutes": 0.0,
        "portability_rework_hours": 0.0,
        "observation_basis": "Measured values only; replace this template before use.",
    }


def build_value_proof(measurement: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _validate_measurement(measurement)
    attempts = normalized["attempted_missions"]
    successes = normalized["successful_missions"]
    safe = normalized["safe_missions"]
    cost = normalized["total_observed_cost"]
    metrics = {
        "mission_success_rate": successes / attempts,
        "safe_mission_rate": safe / attempts,
        "cost_per_attempt": cost / attempts,
        "cost_per_successful_mission": cost / successes if successes else None,
        "cost_per_safe_mission": cost / safe if safe else None,
        "safe_missions_per_currency_unit": safe / cost if cost else None,
        "mean_latency_ms_per_attempt": normalized["total_latency_ms"] / attempts,
        "human_review_minutes_per_safe_mission": normalized["human_review_minutes"] / safe
        if safe
        else None,
        "recovery_minutes_per_attempt": normalized["recovery_minutes"] / attempts,
        "portability_rework_hours_observed": normalized["portability_rework_hours"],
    }
    payload: dict[str, Any] = {
        "schema_version": 1,
        "proof_type": PROOF_TYPE,
        "measurement": normalized,
        "measurement_sha256": canonical_sha256(normalized),
        "metrics": metrics,
        "decision_authority": "accountable mission, acquisition, finance, and risk owners",
        "disclaimer": DISCLAIMER,
    }
    payload["proof_sha256"] = canonical_sha256(payload)
    return payload


def verify_value_proof(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "proof_type",
        "measurement",
        "measurement_sha256",
        "metrics",
        "decision_authority",
        "disclaimer",
        "proof_sha256",
    }
    if set(payload) != fields:
        errors.append("ValueProof fields are incomplete or unsupported")
    if payload.get("schema_version") != 1 or payload.get("proof_type") != PROOF_TYPE:
        errors.append("unsupported ValueProof version or type")
    if payload.get("disclaimer") != DISCLAIMER:
        errors.append("ValueProof disclaimer does not match the frozen protocol")
    try:
        expected = build_value_proof(payload.get("measurement", {}))
    except (TypeError, ValueError) as exc:
        errors.append(f"invalid ValueProof measurement: {exc}")
    else:
        for field in ("measurement_sha256", "metrics", "decision_authority", "proof_sha256"):
            if payload.get(field) != expected[field]:
                errors.append(f"ValueProof {field} does not recompute")
    return tuple(dict.fromkeys(errors))


def compare_value_proofs(proofs: list[Mapping[str, Any]]) -> dict[str, Any]:
    if len(proofs) < 2:
        raise ValueError("ValueProof comparison requires at least two observations")
    normalized = []
    for index, proof in enumerate(proofs):
        errors = verify_value_proof(proof)
        if errors:
            raise ValueError(f"invalid ValueProof at index {index}: {'; '.join(errors)}")
        normalized.append(dict(proof))
    first = normalized[0]["measurement"]
    comparable = all(
        proof["measurement"][field] == first[field]
        for proof in normalized[1:]
        for field in ("mission_id", "protocol_sha256", "currency", "boundary")
    )
    reasons = []
    for field in ("mission_id", "protocol_sha256", "currency", "boundary"):
        if len({json.dumps(item["measurement"][field], sort_keys=True) for item in normalized}) > 1:
            reasons.append(f"{field} differs")
    comparison: dict[str, Any] = {
        "schema_version": 1,
        "comparison_type": COMPARISON_TYPE,
        "comparable": comparable,
        "non_comparability_reasons": reasons,
        "candidates": [
            {
                "candidate": proof["measurement"]["candidate"],
                "measurement_id": proof["measurement"]["measurement_id"],
                "proof_sha256": proof["proof_sha256"],
                "metrics": proof["metrics"],
            }
            for proof in normalized
        ],
        "ranking": "not_computed",
        "decision_authority": "accountable mission, acquisition, finance, and risk owners",
        "disclaimer": DISCLAIMER,
    }
    comparison["comparison_sha256"] = canonical_sha256(comparison)
    return comparison


def _validate_measurement(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _INPUT_FIELDS:
        raise ValueError("measurement fields are incomplete or unsupported")
    normalized = json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    if normalized.get("schema_version") != 1:
        raise ValueError("measurement schema_version must be 1")
    for field in (
        "mission_id",
        "measurement_id",
        "candidate",
        "protocol_sha256",
        "boundary",
        "currency",
        "observation_basis",
    ):
        if not isinstance(normalized.get(field), str) or not normalized[field].strip():
            raise ValueError(f"measurement {field} must be non-empty")
    digest = normalized["protocol_sha256"]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("measurement protocol_sha256 must be a SHA-256 digest")
    attempts = normalized.get("attempted_missions")
    successes = normalized.get("successful_missions")
    safe = normalized.get("safe_missions")
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1:
        raise ValueError("attempted_missions must be a positive integer")
    for field, current in (("successful_missions", successes), ("safe_missions", safe)):
        if (
            not isinstance(current, int)
            or isinstance(current, bool)
            or not 0 <= current <= attempts
        ):
            raise ValueError(f"{field} must be an integer between 0 and attempted_missions")
    if safe > successes:
        raise ValueError("safe_missions cannot exceed successful_missions")
    for field in (
        "total_observed_cost",
        "total_latency_ms",
        "human_review_minutes",
        "recovery_minutes",
        "portability_rework_hours",
    ):
        current = normalized.get(field)
        if not isinstance(current, (int, float)) or isinstance(current, bool) or current < 0:
            raise ValueError(f"measurement {field} must be a non-negative number")
    return normalized
