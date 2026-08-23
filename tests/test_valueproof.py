import json
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pytest

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.value.proof import (
    build_value_proof,
    compare_value_proofs,
    measurement_template,
    verify_value_proof,
)


def measured(candidate="candidate-a"):
    payload = measurement_template()
    payload.update(
        candidate=candidate,
        measurement_id=f"observation-{candidate}",
        successful_missions=90,
        safe_missions=80,
        total_observed_cost=100.0,
        total_latency_ms=50_000.0,
        human_review_minutes=160.0,
        recovery_minutes=20.0,
        portability_rework_hours=4.0,
        observation_basis="Metered synthetic mission execution and recorded review time.",
    )
    return payload


def test_valueproof_computes_only_observed_arithmetic():
    proof = build_value_proof(measured())
    assert proof["metrics"]["safe_mission_rate"] == 0.8
    assert proof["metrics"]["cost_per_safe_mission"] == 1.25
    assert proof["metrics"]["human_review_minutes_per_safe_mission"] == 2.0
    assert verify_value_proof(proof) == ()
    schema = json.loads(
        files("dspy_security_bench").joinpath("schemas/valueproof.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(proof)


def test_valueproof_rejects_unsafe_or_inconsistent_inputs():
    payload = measured()
    payload["safe_missions"] = 91
    with pytest.raises(ValueError, match="cannot exceed"):
        build_value_proof(payload)
    proof = build_value_proof(measured())
    tampered = deepcopy(proof)
    tampered["metrics"]["cost_per_safe_mission"] = 0
    assert "ValueProof metrics does not recompute" in verify_value_proof(tampered)


def test_valueproof_comparison_refuses_non_equivalent_boundaries():
    first = build_value_proof(measured("a"))
    second_measurement = measured("b")
    second_measurement["boundary"] = "Different accounting boundary"
    comparison = compare_value_proofs([first, build_value_proof(second_measurement)])
    assert comparison["comparable"] is False
    assert "boundary differs" in comparison["non_comparability_reasons"]
    assert comparison["ranking"] == "not_computed"


def test_valueproof_cli_round_trip(tmp_path):
    measurement = tmp_path / "measurement.json"
    measurement.write_text(json.dumps(measured()))
    proof = tmp_path / "proof.json"
    assert root_main(["value", "build", str(measurement), "--out", str(proof)]) == 0
    assert root_main(["value", "verify", str(proof)]) == 0
