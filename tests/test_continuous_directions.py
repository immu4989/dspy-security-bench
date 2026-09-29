"""Metric-name substrings must not decide whether an outcome is an improvement."""

from copy import deepcopy

import pytest

from dspy_security_bench.continuous.proof import (
    build_evidence_snapshot,
    compare_evidence,
    verify_continuous_proof,
    verify_snapshot_source,
)
from dspy_security_bench.evalguard.proof import analyze_scenario, built_in_scenario
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.value.proof import build_value_proof, measurement_template


def rehash(payload):
    payload["proof_sha256"] = canonical_sha256({key: value for key, value in payload.items() if key != "proof_sha256"})
    return payload


def snapshots(metric, old, new):
    # These hand-edited snapshots test the comparator only, not source truth.
    before = build_evidence_snapshot(build_value_proof(measurement_template()), label="fixture")
    before["metrics"] = {metric: old}
    after = deepcopy(before)
    after["metrics"][metric] = new
    return rehash(before), rehash(after)


@pytest.mark.parametrize("metric", [
    "summary.harmful_outcomes", "summary.leakage_canary_hits",
    "summary.probe_status_counts.violation_observed", "summary.control_status_counts.monitor_failed",
    "summary.control_status_counts.incomplete_evidence", "summary.cost_per_safe_mission",
])
def test_known_adverse_metric_increases_are_regressions(metric):
    report = compare_evidence(*snapshots(metric, 0, 1))
    change = report["metric_changes"][0]
    assert change["direction"] == "lower_is_better"
    assert change["regression"] == 1 and change["threshold_exceeded"]
    assert report["status"] == "review"
    assert verify_continuous_proof(report) == ()


@pytest.mark.parametrize("metric", ["summary.requirements_met", "summary.attack_resistance",
    "summary.safe_missions_per_currency_unit", "summary.cells." + "a" * 64 + ".utility_rate"])
def test_known_beneficial_metric_increases_remain_improvements(metric):
    report = compare_evidence(*snapshots(metric, 0, 1))
    assert report["metric_changes"][0]["direction"] == "higher_is_better"
    assert not report["metric_changes"][0]["threshold_exceeded"]
    assert report["status"] == "within_threshold"


@pytest.mark.parametrize("metric", ["summary.high_quality", "summary.low_latency_score",
    "summary.new_measure", "summary.user.high", "summary.cells.untrusted.utility_rate"])
@pytest.mark.parametrize("new", [0, 2])
def test_unfamiliar_metrics_do_not_get_an_inferred_preference(metric, new):
    report = compare_evidence(*snapshots(metric, 1, new), max_regression=1000)
    assert report["metric_changes"][0]["direction"] == "change_requires_review"
    assert report["metric_changes"][0]["regression"] == 1
    assert report["metric_changes"][0]["threshold_exceeded"]
    assert report["status"] == "review"
    assert verify_continuous_proof(report) == ()


def test_unchanged_unfamiliar_metric_is_not_called_a_regression():
    report = compare_evidence(*snapshots("summary.new_measure", 1, 1))
    assert report["status"] == "within_threshold"
    assert not report["metric_changes"][0]["threshold_exceeded"]


def test_native_leakage_evidence_has_correct_direction_after_source_verification():
    baseline_source = analyze_scenario(built_in_scenario("integrity-reference"))
    candidate_source = analyze_scenario(built_in_scenario("label-leakage"))
    baseline = build_evidence_snapshot(baseline_source, label="before")
    candidate = build_evidence_snapshot(candidate_source, label="after")
    assert verify_snapshot_source(baseline, baseline_source) == ()
    assert verify_snapshot_source(candidate, candidate_source) == ()
    report = compare_evidence(baseline, candidate)
    leakage = next(item for item in report["metric_changes"] if item["metric"] == "summary.leakage_canary_hits")
    assert leakage["direction"] == "lower_is_better" and leakage["threshold_exceeded"]


@pytest.mark.parametrize("before_identity,after_identity", [({"version": 1}, {"version": True}),
    ({"version": None}, {}), ({}, {"version": None})])
def test_identity_changes_are_typed_and_preserve_field_presence(before_identity, after_identity):
    before, after = snapshots("summary.attack_resistance", 1, 1)
    before["identity"], after["identity"] = before_identity, after_identity
    report = compare_evidence(rehash(before), rehash(after))
    assert report["status"] == "review"
    assert len(report["identity_changes"]) == 1


def test_rehashed_old_incorrect_direction_cannot_verify_as_a_current_report():
    report = compare_evidence(*snapshots("summary.harmful_outcomes", 0, 1))
    report["metric_changes"][0].update(direction="higher_is_better", regression=0, threshold_exceeded=False)
    report["status"] = "within_threshold"
    assert verify_continuous_proof(rehash(report))
