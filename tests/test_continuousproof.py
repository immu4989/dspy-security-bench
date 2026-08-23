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
from dspy_security_bench.graph.benchmark import run_agent_graph_twin


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
