"""Native control verification must distinguish JSON booleans, counts, and rates."""

from copy import deepcopy

import pytest

from dspy_security_bench.procurement.agents import build_vulnerable_reference
from dspy_security_bench.procurement.control_twin import run_control_twin, verify_control_report
from dspy_security_bench.procurement.repeat_control import (
    run_repeat_control_twin,
    verify_repeat_control_report,
)
from dspy_security_bench.procurement.validation import measurement_matches
from tests.test_control_twin import _procurement_policy, _rehash


@pytest.fixture(scope="module")
def report():
    return run_control_twin(build_vulnerable_reference, _procurement_policy()).to_dict()


@pytest.fixture(scope="module")
def repeated():
    return run_repeat_control_twin(build_vulnerable_reference, _procurement_policy(), trials=2).to_dict()


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(schema_version=True),
    lambda r: r["summary"].update(counterfactual_pairs=5.0),
    lambda r: r["summary"].update(controlled_harmful_pairs=False),
    lambda r: r["pairs"][0].update(harm_contained=1),
    lambda r: r["pairs"][0].update(baseline_attack_resisted=0),
    lambda r: r["pairs"][0]["policy_events"][0].update(index=False),
    lambda r: r["pairs"][0]["policy_events"][0].update(approval_required=0),
    lambda r: r["pairs"][0]["policy_events"][0].update(allowed=1),
    lambda r: r["pairs"][0]["policy_events"][0].update(approved=0),
    lambda r: r["pairs"][0]["policy_events"][0].update(arguments=[]),
    lambda r: r["pairs"][0]["policy_events"][0].update(rule_id=[]),
    lambda r: r["pairs"][0]["policy_events"][0].update(scenario_id=[]),
    lambda r: r["pairs"][0]["policy_events"][0].pop("arguments"),
    lambda r: r["pairs"][0]["policy_events"].__setitem__(0, None),
    lambda r: r["pairs"][0].update(pair_id=[]),
    lambda r: r["baseline"].update(schema_version=3.0),
    lambda r: r["baseline"]["summary"].update(clean_mission_utility=True),
    lambda r: r["baseline"]["summary"].update(decision_integrity=True),
    lambda r: r["baseline"]["summary"].update(source_selection_records_exposed=999),
    lambda r: r["baseline"]["summary"].update(avoidable_price_premium_usd=999),
    lambda r: r["baseline"]["summary"].update(counterfactual_pairs=5.0),
    lambda r: r["controlled"]["summary"].update(harmful_outcomes=False),
    lambda r: r["baseline"]["summary"]["usage"].update(reported_cases=False),
    lambda r: r["baseline"]["summary"]["usage"].update(total_cases=10.0),
    lambda r: r["baseline"]["summary"]["usage"].update(total_tokens=42),
    lambda r: r["baseline"]["pairs"][0]["clean"].update(synthetic_funds_at_risk_usd=False),
    lambda r: r["baseline"]["pairs"][0]["clean"]["usage"].update(total_tokens=True),
    lambda r: r["baseline"]["pairs"][0]["clean"]["usage"].update(prompt_tokens=1.5),
    lambda r: r["baseline"]["pairs"][0]["clean"]["usage"].update(estimated_cost_usd=-1),
])
def test_rehashed_control_measurement_aliases_are_rejected(report, mutate):
    changed = deepcopy(report)
    mutate(changed)
    _rehash(changed)
    with pytest.raises(ValueError):
        verify_control_report(changed)


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(schema_version=True),
    lambda r: r["trials"][0].update(trial_number=True),
    lambda r: r["summary"].update(trials=2.0),
    lambda r: r["summary"].update(introduced_harm_pair_trials=False),
    lambda r: r["summary"]["controlled_harm_free"].update(successes=10.0),
    lambda r: r["summary"]["controlled_harm_free"].update(rate=True),
    lambda r: r["summary"].update(elapsed_seconds=True),
    lambda r: r["pair_summaries"][0].update(stable_effect=1),
    lambda r: r["policy"].update(arguments_captured=0),
    lambda r: r["summary"]["usage"].update(baseline_reported_cases=False),
])
def test_rehashed_repeated_control_aliases_are_rejected(repeated, mutate):
    changed = deepcopy(repeated)
    mutate(changed)
    _rehash(changed)
    with pytest.raises(ValueError):
        verify_repeat_control_report(changed)


def test_generated_reports_and_integer_spellings_of_real_rates_remain_valid(report, repeated):
    assert isinstance(verify_control_report(report), tuple)
    assert isinstance(verify_repeat_control_report(repeated), tuple)
    changed = deepcopy(report)
    changed["summary"]["baseline_clean_mission_utility"] = 1
    _rehash(changed)
    verify_control_report(changed)


@pytest.mark.parametrize("actual,expected,matches", [
    (True, 1, False), (0, False, False), (1.0, 1, False), (1, 1.0, True),
    (False, 0.0, False), ([True], [1], False), ({"n": 1.0}, {"n": 1}, False),
    (float("inf"), float("inf"), False), (10**1000, 1.0, False),
    (None, None, True), ({"n": 2}, {"n": 2}, True),
])
def test_recursive_measurement_comparison(actual, expected, matches):
    assert measurement_matches(actual, expected) is matches


@pytest.mark.parametrize("source", [None, [], True])
def test_bad_roots_have_stable_value_errors(source):
    with pytest.raises(ValueError):
        verify_control_report(source)
    with pytest.raises(ValueError):
        verify_repeat_control_report(source)


def test_rehashing_every_layer_cannot_admit_invalid_nested_policy_measurements(repeated):
    from dspy_security_bench.procurement.control_registry import (
        create_control_submission_bundle,
        verify_control_submission_bundle,
    )
    from dspy_security_bench.procurement.repeat import canonical_sha256
    from dspy_security_bench.procurement.sharing import create_sharing_review

    bundle = create_control_submission_bundle(
        repeated, submitter="synthetic-test", agent_source_url="https://example.com/agent",
        policy_source_url="https://example.com/policy",
    )
    source = bundle["report"] = deepcopy(bundle["report"])
    control = source["trials"][0]["control"]
    control["pairs"][0]["policy_events"][0]["index"] = False
    _rehash(control)
    _rehash(source)
    bundle["report_sha256"] = canonical_sha256(source)
    bundle.pop("bundle_sha256")
    bundle["bundle_sha256"] = canonical_sha256(bundle)
    assert not verify_control_submission_bundle(bundle).valid
    with pytest.raises(ValueError, match="native"):
        create_sharing_review(bundle)
