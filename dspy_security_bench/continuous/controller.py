"""Observe-only continuous assurance controller and append-only evidence timelines."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from copy import deepcopy
from typing import Any

from dspy_security_bench.continuous.proof import (
    SNAPSHOT_TYPE,
    build_evidence_snapshot,
    compare_evidence,
    verify_continuous_proof,
)
from dspy_security_bench.mission.loader import canonical_sha256

PLAN_TYPE = "dspy-security-bench-assurance-observation-plan"
OBSERVATION_TYPE = "dspy-security-bench-assurance-observation"
TIMELINE_TYPE = "dspy-security-bench-assurance-timeline"
CONTROLLER_VERSION = "continuousproof-controller-v1"
DISCLAIMER = (
    "The ContinuousProof controller is observe-only: it reads owner-selected evidence, verifies "
    "it offline, evaluates freshness and owner thresholds, and emits review evidence. It never "
    "contains workloads, changes production state, accepts risk, schedules itself, or authorizes "
    "deployment. Operators retain all response and scheduling decisions."
)
_SAFE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,119}$")
_PLAN_FIELDS = {
    "schema_version",
    "controller_type",
    "controller_version",
    "plan_id",
    "evaluation_time",
    "mode",
    "jobs",
    "owner_policy",
    "claim_boundary",
    "plan_sha256",
}
_JOB_FIELDS = {
    "job_id",
    "evidence_ref",
    "expected_evidence_kind",
    "last_updated_at",
    "max_age_seconds",
    "max_regression",
    "baseline",
}
_POLICY_FIELDS = {"review_on_stale", "review_on_invalid", "review_on_regression"}


def build_plan(
    *,
    plan_id: str,
    evaluation_time: int,
    jobs: list[dict[str, Any]],
    owner_policy: dict[str, bool] | None = None,
) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "schema_version": 1,
        "controller_type": PLAN_TYPE,
        "controller_version": CONTROLLER_VERSION,
        "plan_id": plan_id,
        "evaluation_time": evaluation_time,
        "mode": "observe_only",
        "jobs": deepcopy(jobs),
        "owner_policy": deepcopy(
            owner_policy
            or {
                "review_on_stale": True,
                "review_on_invalid": True,
                "review_on_regression": True,
            }
        ),
        "claim_boundary": DISCLAIMER,
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    errors = verify_plan(plan)
    if errors:
        raise ValueError("invalid observation plan: " + "; ".join(errors))
    return plan


def verify_plan(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if set(payload) != _PLAN_FIELDS:
        errors.append("observation plan fields are incomplete or unsupported")
    if (
        payload.get("schema_version") != 1
        or payload.get("controller_type") != PLAN_TYPE
        or payload.get("controller_version") != CONTROLLER_VERSION
        or payload.get("mode") != "observe_only"
        or payload.get("claim_boundary") != DISCLAIMER
    ):
        errors.append("observation plan metadata is unsupported")
    _safe(payload.get("plan_id"), "plan_id", errors)
    _timestamp(payload.get("evaluation_time"), "evaluation_time", errors)
    jobs = payload.get("jobs")
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= 1000:
        errors.append("jobs must contain between 1 and 1000 objects")
        jobs = []
    job_ids: set[str] = set()
    for index, job in enumerate(jobs):
        label = f"jobs[{index}]"
        if not isinstance(job, Mapping) or set(job) != _JOB_FIELDS:
            errors.append(f"{label} fields are incomplete or unsupported")
            continue
        _safe(job.get("job_id"), f"{label}.job_id", errors)
        _safe(job.get("evidence_ref"), f"{label}.evidence_ref", errors)
        _safe(job.get("expected_evidence_kind"), f"{label}.expected_evidence_kind", errors)
        _timestamp(job.get("last_updated_at"), f"{label}.last_updated_at", errors)
        max_age = job.get("max_age_seconds")
        if not _is_int(max_age) or not 1 <= max_age <= 31_536_000:
            errors.append(f"{label}.max_age_seconds must be between 1 and 31536000")
        regression = job.get("max_regression")
        if (
            isinstance(regression, bool)
            or not isinstance(regression, (int, float))
            or regression < 0
        ):
            errors.append(f"{label}.max_regression must be a non-negative number")
        baseline = job.get("baseline")
        if baseline is not None:
            if not isinstance(baseline, Mapping):
                errors.append(f"{label}.baseline must be a snapshot or null")
            else:
                baseline_errors = verify_continuous_proof(baseline)
                errors.extend(f"{label}.baseline: {item}" for item in baseline_errors)
                if baseline.get("proof_type") != SNAPSHOT_TYPE:
                    errors.append(f"{label}.baseline must be a ContinuousProof snapshot")
        job_id = job.get("job_id")
        if isinstance(job_id, str):
            if job_id in job_ids:
                errors.append(f"duplicate job_id {job_id!r}")
            job_ids.add(job_id)
    policy = payload.get("owner_policy")
    if not isinstance(policy, Mapping) or set(policy) != _POLICY_FIELDS:
        errors.append("owner_policy fields are incomplete or unsupported")
    elif any(not isinstance(policy[field], bool) for field in _POLICY_FIELDS):
        errors.append("owner_policy values must be boolean")
    unsigned = dict(payload)
    claimed = unsigned.pop("plan_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("plan_sha256 does not match canonical plan content")
    except (TypeError, ValueError):
        errors.append("plan must contain canonical JSON data")
    return tuple(dict.fromkeys(errors))


def observe_plan(
    plan: Mapping[str, Any], evidence_loader: Callable[[str], Mapping[str, Any]]
) -> dict[str, Any]:
    """Verify current evidence through an injected read-only loader; take no response action."""

    errors = verify_plan(plan)
    if errors:
        raise ValueError("invalid observation plan: " + "; ".join(errors))
    observations = []
    for job in plan["jobs"]:
        reasons: list[str] = []
        snapshot = None
        drift = None
        evidence_sha256 = None
        stale = plan["evaluation_time"] - job["last_updated_at"] > job["max_age_seconds"]
        if stale:
            reasons.append("stale")
        try:
            evidence = evidence_loader(job["evidence_ref"])
            evidence_sha256 = canonical_sha256(evidence)
            snapshot = build_evidence_snapshot(evidence, label=job["job_id"])
            if snapshot["evidence_kind"] != job["expected_evidence_kind"]:
                reasons.append("unexpected_evidence_kind")
            if job["baseline"] is not None:
                drift = compare_evidence(
                    job["baseline"], snapshot, max_regression=float(job["max_regression"])
                )
                if drift["status"] == "review":
                    reasons.append("regression")
        except (OSError, TypeError, ValueError) as exc:
            reasons.append("invalid_evidence")
            # Bound diagnostic text and avoid source payloads or stack traces.
            diagnostic = str(exc)[:300]
        else:
            diagnostic = "verified"
        observations.append(
            {
                "job_id": job["job_id"],
                "evidence_ref": job["evidence_ref"],
                "status": "review" if reasons else "within_threshold",
                "reasons": sorted(set(reasons)),
                "diagnostic": diagnostic,
                "stale": stale,
                "evidence_sha256": evidence_sha256,
                "snapshot": snapshot,
                "drift": drift,
            }
        )
    policy = plan["owner_policy"]
    review_reasons = {
        "stale": policy["review_on_stale"],
        "invalid_evidence": policy["review_on_invalid"],
        "unexpected_evidence_kind": policy["review_on_invalid"],
        "regression": policy["review_on_regression"],
    }
    review_required = any(
        review_reasons.get(reason, True)
        for observation in observations
        for reason in observation["reasons"]
    )
    report: dict[str, Any] = {
        "schema_version": 1,
        "controller_type": OBSERVATION_TYPE,
        "controller_version": CONTROLLER_VERSION,
        "mode": "observe_only",
        "plan": deepcopy(dict(plan)),
        "summary": {
            "status": "review_required" if review_required else "within_threshold",
            "job_count": len(observations),
            "review_count": sum(item["status"] == "review" for item in observations),
            "stale_count": sum(item["stale"] for item in observations),
            "invalid_count": sum("invalid_evidence" in item["reasons"] for item in observations),
            "regression_count": sum("regression" in item["reasons"] for item in observations),
            "actions_taken": 0,
        },
        "observations": observations,
        "claim_boundary": DISCLAIMER,
    }
    report["observation_sha256"] = canonical_sha256(report)
    return report


def verify_observation(
    payload: Mapping[str, Any], evidence_loader: Callable[[str], Mapping[str, Any]]
) -> tuple[str, ...]:
    errors = list(verify_observation_envelope(payload))
    plan = payload.get("plan")
    if not isinstance(plan, Mapping) or errors:
        return tuple(dict.fromkeys(errors))
    expected = observe_plan(plan, evidence_loader)
    for field in sorted(set(expected) - {"observation_sha256"}):
        if payload.get(field) != expected.get(field):
            errors.append(f"{field} does not recompute")
    return tuple(dict.fromkeys(errors))


def verify_observation_envelope(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Verify a stored observation and nested proofs without reopening source evidence."""

    fields = {
        "schema_version",
        "controller_type",
        "controller_version",
        "mode",
        "plan",
        "summary",
        "observations",
        "claim_boundary",
        "observation_sha256",
    }
    errors: list[str] = []
    if set(payload) != fields:
        errors.append("observation fields are incomplete or unsupported")
    if (
        payload.get("schema_version") != 1
        or payload.get("controller_type") != OBSERVATION_TYPE
        or payload.get("controller_version") != CONTROLLER_VERSION
        or payload.get("mode") != "observe_only"
        or payload.get("claim_boundary") != DISCLAIMER
    ):
        errors.append("observation metadata is unsupported")
    plan = payload.get("plan")
    if not isinstance(plan, Mapping):
        return ("observation plan must be an object",)
    errors.extend(f"plan: {item}" for item in verify_plan(plan))
    summary = payload.get("summary")
    if not isinstance(summary, Mapping) or summary.get("actions_taken") != 0:
        errors.append("observation summary must declare actions_taken equal to zero")
    observations = payload.get("observations")
    if not isinstance(observations, list) or len(observations) != len(plan.get("jobs", [])):
        errors.append("observation jobs do not match the plan")
        observations = []
    observation_fields = {
        "job_id",
        "evidence_ref",
        "status",
        "reasons",
        "diagnostic",
        "stale",
        "evidence_sha256",
        "snapshot",
        "drift",
    }
    for index, observation in enumerate(observations):
        if not isinstance(observation, Mapping) or set(observation) != observation_fields:
            errors.append(f"observations[{index}] fields are incomplete or unsupported")
            continue
        snapshot = observation.get("snapshot")
        if snapshot is not None:
            if not isinstance(snapshot, Mapping):
                errors.append(f"observations[{index}].snapshot must be an object or null")
            else:
                errors.extend(
                    f"observations[{index}].snapshot: {item}"
                    for item in verify_continuous_proof(snapshot)
                )
                if snapshot.get("evidence_sha256") != observation.get("evidence_sha256"):
                    errors.append(f"observations[{index}].evidence_sha256 does not match snapshot")
        drift = observation.get("drift")
        if drift is not None:
            if not isinstance(drift, Mapping):
                errors.append(f"observations[{index}].drift must be an object or null")
            else:
                errors.extend(
                    f"observations[{index}].drift: {item}"
                    for item in verify_continuous_proof(drift)
                )
    unsigned = dict(payload)
    claimed = unsigned.pop("observation_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("observation_sha256 does not match canonical observation content")
    except (TypeError, ValueError):
        errors.append("observation must contain canonical JSON data")
    return tuple(dict.fromkeys(errors))


def append_timeline(
    timeline: Mapping[str, Any] | None,
    observation: Mapping[str, Any],
    *,
    timeline_id: str,
) -> dict[str, Any]:
    """Append a verified-by-construction observation to a hash-chained timeline."""

    _safe_or_raise(timeline_id, "timeline_id")
    observation_errors = verify_observation_envelope(observation)
    if observation_errors:
        raise ValueError("invalid observation: " + "; ".join(observation_errors))
    if timeline is None:
        entries: list[dict[str, Any]] = []
    else:
        errors = verify_timeline(timeline)
        if errors:
            raise ValueError("invalid timeline: " + "; ".join(errors))
        if timeline.get("timeline_id") != timeline_id:
            raise ValueError("timeline_id does not match the existing timeline")
        entries = deepcopy(timeline["entries"])
    observed_at = observation.get("plan", {}).get("evaluation_time")
    if entries and observed_at <= entries[-1]["observed_at"]:
        raise ValueError("timeline observations must have strictly increasing evaluation times")
    if any(
        entry["observation_sha256"] == observation.get("observation_sha256") for entry in entries
    ):
        raise ValueError("timeline observation is already present")
    previous = entries[-1]["entry_sha256"] if entries else None
    entry: dict[str, Any] = {
        "sequence": len(entries) + 1,
        "observed_at": observed_at,
        "previous_entry_sha256": previous,
        "observation": deepcopy(dict(observation)),
        "observation_sha256": observation.get("observation_sha256"),
    }
    entry["entry_sha256"] = canonical_sha256(entry)
    entries.append(entry)
    result: dict[str, Any] = {
        "schema_version": 1,
        "controller_type": TIMELINE_TYPE,
        "controller_version": CONTROLLER_VERSION,
        "timeline_id": timeline_id,
        "entries": entries,
        "claim_boundary": DISCLAIMER,
    }
    result["timeline_sha256"] = canonical_sha256(result)
    return result


def verify_timeline(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "controller_type",
        "controller_version",
        "timeline_id",
        "entries",
        "claim_boundary",
        "timeline_sha256",
    }
    if set(payload) != fields:
        errors.append("timeline fields are incomplete or unsupported")
    if (
        payload.get("schema_version") != 1
        or payload.get("controller_type") != TIMELINE_TYPE
        or payload.get("controller_version") != CONTROLLER_VERSION
        or payload.get("claim_boundary") != DISCLAIMER
    ):
        errors.append("timeline metadata is unsupported")
    _safe(payload.get("timeline_id"), "timeline_id", errors)
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("timeline entries must be a non-empty list")
        entries = []
    previous = None
    prior_observed_at = None
    observation_digests: set[str] = set()
    for index, entry in enumerate(entries):
        expected_fields = {
            "sequence",
            "observed_at",
            "previous_entry_sha256",
            "observation",
            "observation_sha256",
            "entry_sha256",
        }
        if not isinstance(entry, Mapping) or set(entry) != expected_fields:
            errors.append(f"entries[{index}] fields are incomplete or unsupported")
            continue
        if entry.get("sequence") != index + 1:
            errors.append(f"entries[{index}].sequence is not contiguous")
        if entry.get("previous_entry_sha256") != previous:
            errors.append(f"entries[{index}].previous_entry_sha256 breaks the chain")
        observed_at = entry.get("observed_at")
        if not _is_int(observed_at) or (
            prior_observed_at is not None and observed_at <= prior_observed_at
        ):
            errors.append(f"entries[{index}].observed_at must be strictly increasing")
        observation = entry.get("observation")
        if not isinstance(observation, Mapping):
            errors.append(f"entries[{index}].observation must be an object")
        else:
            errors.extend(
                f"entries[{index}].observation: {item}"
                for item in verify_observation_envelope(observation)
            )
            if entry.get("observation_sha256") != observation.get("observation_sha256"):
                errors.append(f"entries[{index}].observation_sha256 does not match")
        observation_digest = entry.get("observation_sha256")
        if observation_digest in observation_digests:
            errors.append(f"entries[{index}].observation_sha256 is replayed")
        elif isinstance(observation_digest, str):
            observation_digests.add(observation_digest)
        unsigned = dict(entry)
        claimed = unsigned.pop("entry_sha256", None)
        try:
            if claimed != canonical_sha256(unsigned):
                errors.append(f"entries[{index}].entry_sha256 does not match")
        except (TypeError, ValueError):
            errors.append(f"entries[{index}] is not canonical JSON data")
        previous = entry.get("entry_sha256")
        prior_observed_at = observed_at if _is_int(observed_at) else prior_observed_at
    unsigned_timeline = dict(payload)
    claimed_timeline = unsigned_timeline.pop("timeline_sha256", None)
    try:
        if claimed_timeline != canonical_sha256(unsigned_timeline):
            errors.append("timeline_sha256 does not match canonical timeline content")
    except (TypeError, ValueError):
        errors.append("timeline is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def _safe(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _SAFE.fullmatch(value):
        errors.append(f"{label} must be a safe identifier")


def _safe_or_raise(value: Any, label: str) -> None:
    errors: list[str] = []
    _safe(value, label, errors)
    if errors:
        raise ValueError(errors[0])


def _timestamp(value: Any, label: str, errors: list[str]) -> None:
    if not _is_int(value) or value < 0:
        errors.append(f"{label} must be a non-negative integer Unix timestamp")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
