"""Tamper-evident assurance baselines and regression reports."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256

SNAPSHOT_TYPE = "dspy-security-bench-continuousproof-snapshot"
DRIFT_TYPE = "dspy-security-bench-continuousproof-drift"
DISCLAIMER = (
    "ContinuousProof reports verified evidence change; thresholds and acceptance remain owner "
    "decisions. It is not continuous monitoring of a production system, certification, a risk "
    "acceptance, compliance determination, or authorization to operate."
)
_LOWER_IS_BETTER = (
    "unsafe",
    "false",
    "error",
    "failure",
    "blast",
    "harm_event",
    "finding",
    "critical",
    "high",
    "medium",
    "low",
    "cost",
    "latency",
    "minutes",
    "rework",
)
_NON_METRICS = ("count", "trials", "seconds", "pair_count")


def build_evidence_snapshot(payload: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    """Verify a supported report and capture its comparable identity and numeric metrics."""

    if not isinstance(label, str) or not label.strip():
        raise ValueError("snapshot label must be non-empty")
    kind, errors = _verify_evidence(payload)
    if errors:
        raise ValueError("evidence verification failed: " + "; ".join(errors))
    summary = payload.get("metrics", {}) if kind == "value" else payload.get("summary", {})
    snapshot: dict[str, Any] = {
        "schema_version": 1,
        "proof_type": SNAPSHOT_TYPE,
        "label": label.strip(),
        "evidence_kind": kind,
        "evidence_sha256": canonical_sha256(payload),
        "identity": _identity(payload),
        "metrics": _metrics(summary if isinstance(summary, Mapping) else {}),
        "disclaimer": DISCLAIMER,
    }
    snapshot["proof_sha256"] = canonical_sha256(snapshot)
    return snapshot


def compare_evidence(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    max_regression: float = 0.0,
) -> dict[str, Any]:
    """Compare two valid snapshots without deciding whether deployment risk is acceptable."""

    for name, snapshot in (("baseline", baseline), ("candidate", candidate)):
        errors = verify_continuous_proof(snapshot)
        if errors or snapshot.get("proof_type") != SNAPSHOT_TYPE:
            detail = "; ".join(errors) if errors else "not a snapshot"
            raise ValueError(f"invalid {name} snapshot: {detail}")
    if baseline.get("evidence_kind") != candidate.get("evidence_kind"):
        raise ValueError("snapshots use different evidence kinds")
    if isinstance(max_regression, bool) or not isinstance(max_regression, (int, float)):
        raise ValueError("max_regression must be a non-negative number")
    if max_regression < 0:
        raise ValueError("max_regression must be a non-negative number")
    before = baseline.get("metrics", {})
    after = candidate.get("metrics", {})
    common = sorted(set(before) & set(after))
    changes = []
    for metric in common:
        old, new = float(before[metric]), float(after[metric])
        direction = "lower_is_better" if _lower_is_better(metric) else "higher_is_better"
        regression = new - old if direction == "lower_is_better" else old - new
        changes.append(
            {
                "metric": metric,
                "baseline": old,
                "candidate": new,
                "delta": new - old,
                "direction": direction,
                "regression": max(0.0, regression),
                "threshold_exceeded": regression > float(max_regression),
            }
        )
    identity_changes = [
        {
            "field": field,
            "baseline": baseline["identity"].get(field),
            "candidate": candidate["identity"].get(field),
        }
        for field in sorted(set(baseline["identity"]) | set(candidate["identity"]))
        if baseline["identity"].get(field) != candidate["identity"].get(field)
    ]
    report: dict[str, Any] = {
        "schema_version": 1,
        "proof_type": DRIFT_TYPE,
        "evidence_kind": baseline["evidence_kind"],
        "baseline": dict(baseline),
        "candidate": dict(candidate),
        "policy": {"max_regression": float(max_regression), "owner_supplied": True},
        "identity_changes": identity_changes,
        "metric_changes": changes,
        "status": "review"
        if identity_changes or any(item["threshold_exceeded"] for item in changes)
        else "within_threshold",
        "disclaimer": DISCLAIMER,
    }
    report["proof_sha256"] = canonical_sha256(report)
    return report


def verify_continuous_proof(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    proof_type = payload.get("proof_type")
    if proof_type not in {SNAPSHOT_TYPE, DRIFT_TYPE}:
        return ("unsupported ContinuousProof type",)
    claimed = payload.get("proof_sha256")
    unsigned = dict(payload)
    unsigned.pop("proof_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("proof_sha256 does not match canonical proof content")
    except (TypeError, ValueError):
        errors.append("proof is not canonical JSON data")
    if payload.get("schema_version") != 1 or payload.get("disclaimer") != DISCLAIMER:
        errors.append("proof metadata does not match ContinuousProof v1")
    if proof_type == SNAPSHOT_TYPE:
        snapshot_fields = {
            "schema_version",
            "proof_type",
            "label",
            "evidence_kind",
            "evidence_sha256",
            "identity",
            "metrics",
            "disclaimer",
            "proof_sha256",
        }
        if set(payload) != snapshot_fields:
            errors.append("snapshot fields are incomplete or unsupported")
        if not isinstance(payload.get("label"), str) or not payload["label"].strip():
            errors.append("snapshot label must be non-empty")
        if (
            not isinstance(payload.get("evidence_kind"), str)
            or not payload["evidence_kind"].strip()
        ):
            errors.append("snapshot evidence_kind must be non-empty")
        identity, metrics = payload.get("identity"), payload.get("metrics")
        if not isinstance(identity, Mapping) or not isinstance(metrics, Mapping):
            errors.append("snapshot identity and metrics must be objects")
        elif not all(
            isinstance(key, str) and isinstance(value, (int, float)) and not isinstance(value, bool)
            for key, value in metrics.items()
        ):
            errors.append("snapshot metrics must contain numeric values")
        if not _digest(payload.get("evidence_sha256")):
            errors.append("snapshot evidence_sha256 must be a SHA-256 digest")
        return tuple(dict.fromkeys(errors))
    drift_fields = {
        "schema_version",
        "proof_type",
        "evidence_kind",
        "baseline",
        "candidate",
        "policy",
        "identity_changes",
        "metric_changes",
        "status",
        "disclaimer",
        "proof_sha256",
    }
    if set(payload) != drift_fields:
        errors.append("drift fields are incomplete or unsupported")
    baseline, candidate = payload.get("baseline"), payload.get("candidate")
    if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
        errors.append("drift report must contain baseline and candidate snapshots")
        return tuple(dict.fromkeys(errors))
    errors.extend(f"baseline: {item}" for item in verify_continuous_proof(baseline))
    errors.extend(f"candidate: {item}" for item in verify_continuous_proof(candidate))
    policy = payload.get("policy")
    if isinstance(policy, Mapping):
        try:
            expected = compare_evidence(
                baseline, candidate, max_regression=float(policy.get("max_regression"))
            )
        except (TypeError, ValueError) as exc:
            errors.append(f"drift report cannot recompute: {exc}")
        else:
            for field in (
                "evidence_kind",
                "policy",
                "identity_changes",
                "metric_changes",
                "status",
            ):
                if payload.get(field) != expected.get(field):
                    errors.append(f"drift {field} does not recompute")
    else:
        errors.append("drift policy must be an object")
    return tuple(dict.fromkeys(errors))


def _verify_evidence(payload: Mapping[str, Any]) -> tuple[str, tuple[str, ...]]:
    report_type = payload.get("report_type")
    if report_type == "AgentGraphTwin / Multi-agent authorization-path assurance":
        from dspy_security_bench.graph.benchmark import verify_graph_report

        return "agent-graph", verify_graph_report(payload)
    if report_type == "AgentGraphTwin v2 / Temporal multi-agent authorization assurance":
        from dspy_security_bench.graph.v2 import verify_agent_graph_twin_v2

        return "agent-graph-v2", verify_agent_graph_twin_v2(payload)
    if report_type == "ScheduleProof / Bounded agent authorization interleaving assurance":
        from dspy_security_bench.schedule.proof import verify_schedule_report

        return "schedule", verify_schedule_report(payload)
    if report_type == "CollectiveGuard / Autonomous-agent collective containment assurance":
        from dspy_security_bench.collective.proof import verify_collective_report

        return "collective", verify_collective_report(payload)
    if report_type == "CollectiveGuard v2 / Provenance-aware collective containment assurance":
        from dspy_security_bench.collective.v2 import verify_report

        return "collective-v2", verify_report(payload)
    if report_type == "TraceProof / Privacy-bounded agent trace analysis":
        from dspy_security_bench.trace.proof import verify_trace_report

        return "trace", verify_trace_report(payload)
    if report_type == "AuthorityTwin / Delegated authorization conformance":
        from dspy_security_bench.authority.benchmark import verify_authority_report

        return "authority", verify_authority_report(payload)
    if report_type == "MissionPackTwin / Deterministic source grounding":
        from dspy_security_bench.mission.benchmark import verify_mission_report

        return "mission-source", verify_mission_report(payload)
    if report_type == "IncidentTwin / Synthetic cyber response":
        from dspy_security_bench.incident.benchmark import verify_incident_report

        return "incident", verify_incident_report(payload)
    if payload.get("proof_type") == "dspy-security-bench-valueproof-observation":
        from dspy_security_bench.value.proof import verify_value_proof

        return "value", verify_value_proof(payload)
    raise ValueError(
        "unsupported evidence; use a verified AgentGraphTwin, TraceProof, AuthorityTwin, "
        "MissionPackTwin, IncidentTwin, ScheduleProof, CollectiveGuard, or ValueProof report"
    )


def _identity(payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "protocol_sha256",
        "scenario_sha256",
        "policy_sha256",
        "scenario_version",
        "adapter",
        "agent",
        "pack_id",
        "source_evidence_sha256",
    )
    identity = {field: payload[field] for field in fields if field in payload}
    measurement = payload.get("measurement")
    if isinstance(measurement, Mapping):
        for field in ("mission_id", "candidate", "protocol_sha256", "currency", "boundary"):
            if field in measurement:
                identity[field] = measurement[field]
    return identity


def _metrics(summary: Mapping[str, Any], prefix: str = "summary") -> dict[str, float]:
    result: dict[str, float] = {}
    for key, value in summary.items():
        name = f"{prefix}.{key}"
        if isinstance(value, Mapping):
            result.update(_metrics(value, name))
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            if not any(token in key.lower() for token in _NON_METRICS):
                result[name] = float(value)
    return dict(sorted(result.items()))


def _lower_is_better(metric: str) -> bool:
    return any(token in metric.lower() for token in _LOWER_IS_BETTER)


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )
