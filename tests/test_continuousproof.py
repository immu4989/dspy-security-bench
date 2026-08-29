import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.authority.adapter import build_bounded_authority_adapter
from dspy_security_bench.continuous.proof import (
    build_evidence_snapshot,
    compare_evidence,
    verify_continuous_proof,
)
from dspy_security_bench.defend.protocol import (
    analyze_remediation,
    built_in_mission,
    built_in_proposal,
)
from dspy_security_bench.graph.benchmark import run_agent_graph_twin
from dspy_security_bench.graph.v2 import (
    build_bounded_temporal_graph_adapter,
    run_agent_graph_twin_v2,
)
from dspy_security_bench.trace.proof import (
    analyze_trace_evidence,
    build_trace_evidence,
    demo_otlp_payload,
)
from dspy_security_bench.value.proof import build_value_proof, measurement_template


def _report():
    return run_agent_graph_twin(
        build_bounded_authority_adapter(), adapter_factory=build_bounded_authority_adapter
    )


def test_snapshot_and_unchanged_comparison_are_offline_verifiable():
    baseline = build_evidence_snapshot(_report(), label="production candidate 1")
    candidate = build_evidence_snapshot(_report(), label="production candidate 2")
    drift = compare_evidence(baseline, candidate)
    assert drift["status"] == "within_threshold"
    assert verify_continuous_proof(baseline) == ()
    assert verify_continuous_proof(drift) == ()
    schema = json.loads(
        files("dspy_security_bench").joinpath("schemas/continuous-proof.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(drift)


def test_owner_threshold_detects_regression_without_accepting_risk():
    baseline = build_evidence_snapshot(_report(), label="baseline")
    candidate = deepcopy(baseline)
    candidate["label"] = "candidate"
    candidate["metrics"]["summary.attack_resistance"] = 0.8
    candidate.pop("proof_sha256")
    from dspy_security_bench.mission.loader import canonical_sha256

    candidate["proof_sha256"] = canonical_sha256(candidate)
    drift = compare_evidence(baseline, candidate, max_regression=0.05)
    assert drift["status"] == "review"
    assert any(item["threshold_exceeded"] for item in drift["metric_changes"])
    assert verify_continuous_proof(drift) == ()


def test_proof_digest_tampering_is_rejected():
    baseline = build_evidence_snapshot(_report(), label="baseline")
    baseline["label"] = "changed"
    assert "proof_sha256 does not match canonical proof content" in verify_continuous_proof(
        baseline
    )


def test_rehashed_extra_continuous_claim_is_rejected():
    baseline = build_evidence_snapshot(_report(), label="baseline")
    baseline["certification"] = True
    baseline.pop("proof_sha256")
    from dspy_security_bench.mission.loader import canonical_sha256

    baseline["proof_sha256"] = canonical_sha256(baseline)
    assert "snapshot fields are incomplete or unsupported" in verify_continuous_proof(baseline)


def test_continuousproof_accepts_trace_graph_v2_and_value_evidence():
    trace = analyze_trace_evidence(build_trace_evidence(demo_otlp_payload()))
    graph = run_agent_graph_twin_v2(
        build_bounded_temporal_graph_adapter(),
        adapter_factory=build_bounded_temporal_graph_adapter,
    )
    measurement = measurement_template()
    measurement.update(successful_missions=90, safe_missions=80, total_observed_cost=100.0)
    value = build_value_proof(measurement)
    snapshots = [
        build_evidence_snapshot(trace, label="trace"),
        build_evidence_snapshot(graph, label="graph-v2"),
        build_evidence_snapshot(value, label="value"),
    ]
    assert [item["evidence_kind"] for item in snapshots] == ["trace", "agent-graph-v2", "value"]
    assert all(verify_continuous_proof(item) == () for item in snapshots)
    assert snapshots[0]["metrics"]["summary.critical"] == 2.0
    assert snapshots[2]["metrics"]["summary.cost_per_safe_mission"] == 1.25


def test_continuousproof_detects_verified_defense_regression():
    mission = built_in_mission("community-hospital")
    safe_report = analyze_remediation(mission, built_in_proposal(mission, "bounded-reference"))
    disruptive_report = analyze_remediation(
        mission, built_in_proposal(mission, "disruptive-reference")
    )

    baseline = build_evidence_snapshot(safe_report, label="bounded remediation")
    candidate = build_evidence_snapshot(disruptive_report, label="disruptive remediation")
    drift = compare_evidence(baseline, candidate)

    assert baseline["evidence_kind"] == "verified-defense"
    assert baseline["metrics"]["summary.mission_stability"] == 1.0
    assert baseline["metrics"]["summary.attack_path_closure_rate"] == 1.0
    assert drift["status"] == "review"
    assert any(
        change["metric"] == "summary.mission_stability" and change["threshold_exceeded"]
        for change in drift["metric_changes"]
    )
    assert verify_continuous_proof(drift) == ()
