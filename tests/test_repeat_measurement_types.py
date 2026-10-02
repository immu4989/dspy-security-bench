"""Truthy strings and bool/int equality must not validate malformed evidence."""

import json
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pytest

from dspy_security_bench.procurement.agents import ReferenceProcurementAgent
from dspy_security_bench.procurement.repeat import (
    canonical_sha256,
    create_submission_bundle,
    run_repeat_twin,
    validate_repeat_payload,
    verify_submission_bundle,
)


@pytest.fixture(scope="module")
def report():
    return run_repeat_twin(ReferenceProcurementAgent(vulnerable=False), trials=2).to_dict()


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(schema_version=True),
    lambda r: r.update(trial_isolation=[]),
    lambda r: r.update(statistical_method="universal certainty"),
    lambda r: r.update(inference_scope="certified production reliability"),
    lambda r: r["summary"].update(case_errors=False),
    lambda r: r["summary"].update(trials=2.0),
    lambda r: r["summary"].update(elapsed_seconds=True),
    lambda r: r["summary"].update(elapsed_seconds=float("inf")),
    lambda r: r["summary"]["attack_resistance"].update(rate=True),
    lambda r: r["summary"]["attack_resistance"].update(successes=10.0),
    lambda r: r["summary"]["attack_resistance"].update(lower=10**1000),
    lambda r: r["summary"]["attack_resistance"].update(approved=True),
    lambda r: r["summary"]["usage"].update(reported_cases=False),
    lambda r: r["pair_summaries"][0].update(stable_outcome=1),
    lambda r: r["pair_summaries"][0].update(error_runs=False),
    lambda r: r["pair_summaries"][0].update(outcome_counts={"resisted": 2.0}),
    lambda r: r["pair_summaries"][0].update(pair_id=[]),
    lambda r: r["pair_summaries"].__setitem__(1, deepcopy(r["pair_summaries"][0])),
    lambda r: r["trials"][0].update(schema_version=[]),
    lambda r: r["trials"][0]["pairs"].__setitem__(0, None),
    lambda r: r["trials"][0]["pairs"][0].update(attack_resisted="false"),
    lambda r: r["trials"][0]["pairs"][0].update(decision_invariant=1),
    lambda r: r["trials"][0]["pairs"][0].update(pair_id=[]),
    lambda r: r["trials"][0]["pairs"][0].update(causal_evidence={}),
    lambda r: r["trials"][0]["pairs"][0]["causal_evidence"].update(first_divergence_index=False),
    lambda r: r["trials"][0]["pairs"][0]["clean"].update(mission_completed="false"),
    lambda r: r["trials"][0]["pairs"][0]["clean"].update(error=0),
    lambda r: r["trials"][0]["pairs"][0]["clean"].update(variant="injected"),
    lambda r: r["trials"][0]["pairs"][0]["clean"].update(prohibited_side_effects=""),
    lambda r: r["trials"][0]["pairs"][0]["clean"].update(usage={"total_tokens": False}),
    lambda r: r["trials"][0]["pairs"][0]["clean"].update(usage={"estimated_cost_usd": 10**1000}),
])
def test_malformed_measurements_return_errors_before_aggregation(report, mutation):
    changed = deepcopy(report)
    mutation(changed)
    assert validate_repeat_payload(changed)


@pytest.mark.parametrize("payload", [None, [], True, 1, "private-value", {}])
def test_invalid_root_is_an_error_not_an_unhandled_exception(payload):
    assert validate_repeat_payload(payload)


def test_generated_report_is_not_mutated_and_still_verifies(report):
    original = deepcopy(report)
    assert validate_repeat_payload(report) == ()
    assert report == original


def test_supported_v2_trial_measurements_still_verify(report):
    changed = deepcopy(report)
    for trial in changed["trials"]:
        trial["schema_version"] = 2
    assert validate_repeat_payload(changed) == ()


@pytest.mark.parametrize("mutation", [
    lambda r: r["trials"][0]["pairs"][0]["clean"].update(mission_completed="false"),
    lambda r: r["trials"][0]["pairs"][0].update(attack_resisted=1),
    lambda r: r["summary"]["usage"].update(total_tokens=True),
    lambda r: r["trials"][0]["pairs"][0]["causal_evidence"].update(first_divergence_index=False),
    lambda r: r.update(inference_scope="certified"),
])
def test_packaged_schema_rejects_typed_measurement_substitutions(report, mutation):
    schema = json.loads(files("dspy_security_bench.schemas").joinpath("repeat-report.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(report, schema)
    changed = deepcopy(report)
    mutation(changed)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(changed, schema)


def test_bundle_rehash_cannot_bless_a_truthy_false_task_outcome(report):
    bundle = create_submission_bundle(report, submitter="fixture", agent_source_url="https://example.com/fixture")
    assert verify_submission_bundle(bundle).valid
    bundle["report"] = deepcopy(report)
    bundle["report"]["trials"][0]["pairs"][0]["clean"]["mission_completed"] = "false"
    bundle["report_sha256"] = canonical_sha256(bundle["report"])
    bundle["bundle_sha256"] = canonical_sha256({k: v for k, v in bundle.items() if k != "bundle_sha256"})
    result = verify_submission_bundle(bundle)
    assert not result.valid and not result.community_eligible
    assert any("case outcome" in error for error in result.errors)


def test_all_trials_cannot_substitute_an_unrecognized_pair_roster(report):
    changed = deepcopy(report)
    old = changed["trials"][0]["pairs"][0]["pair_id"]
    new = "private-unrecognized-pair"
    for trial in changed["trials"]:
        pair = next(pair for pair in trial["pairs"] if pair["pair_id"] == old)
        pair["pair_id"] = new
        pair["clean"]["pair_id"] = pair["injected"]["pair_id"] = new
    changed["pair_summaries"][0]["pair_id"] = new
    errors = validate_repeat_payload(changed)
    assert errors and all(new not in error for error in errors)
