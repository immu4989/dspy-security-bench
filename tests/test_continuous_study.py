"""Portable study snapshots bind coverage identity and natively replay all inputs."""
import json
from copy import deepcopy

import pytest

from dspy_security_bench.continuous.controller import build_plan, observe_plan, verify_observation
from dspy_security_bench.continuous.proof import (
    build_evidence_snapshot,
    compare_evidence,
    verify_snapshot_source,
)
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.evidence import build_scan_evidence
from dspy_security_bench.scan.study import build_study_plan
from dspy_security_bench.scan.study_bundle import build_study_bundle
from dspy_security_bench.scan.study_demo import build_study_demo_artifacts


def source():
    return json.loads(build_study_demo_artifacts()["before.json"])


def bundle(evidence=None, complete=2, errors=0):
    evidence = source() if evidence is None else evidence
    plan = build_study_plan(evidence, "fictional-monitor-study", 3)
    trials = [{"trial_id": name, "status": "complete", "evidence_sha256": evidence["evidence_sha256"]}
              if i < complete else {"trial_id": name, "status": "execution_error" if i < complete + errors else "missing"}
              for i, name in enumerate(plan["trial_ids"])]
    sources = {trial["trial_id"]: evidence for trial in trials if trial["status"] == "complete"}
    return build_study_bundle(plan, trials, sources)


def snapshot(payload):
    return build_evidence_snapshot(payload, label="fictional-study")


def test_study_snapshot_replays_all_sources_and_separates_conditional_rates_from_coverage():
    payload = bundle()
    result = snapshot(payload)
    assert result["evidence_kind"] == "scan-study"
    assert verify_snapshot_source(result, payload) == ()
    assert result["metrics"]["summary.study_coverage_rate"] == 2 / 3
    assert result["metrics"]["summary.study_security_rate"] == 4 / 6
    assert result["metrics"]["summary.study_utility_rate"] == 5 / 6
    assert result["metrics"]["summary.study_requirements_met"] == 0
    assert "fictional" not in str(result["metrics"])


def test_coverage_change_requires_review_even_when_scalar_threshold_allows_it():
    report = compare_evidence(snapshot(bundle(complete=1)), snapshot(bundle(complete=2)), max_regression=1000)
    assert report["status"] == "review"
    assert {item["field"] for item in report["identity_changes"]} == {"study_completed_trial_ids_sha256"}


def test_same_coverage_security_and_utility_remain_distinct():
    evidence = source()
    rows = deepcopy(evidence["observations"])
    for row in rows:
        row.update(security=1, injection_succeeded=0, utility=0)
    changed = build_scan_evidence(evidence["scope"], evidence["policy"], rows)
    report = compare_evidence(snapshot(bundle(evidence)), snapshot(bundle(changed)))
    changes = {item["metric"]: item for item in report["metric_changes"]}
    assert not changes["summary.study_security_rate"]["threshold_exceeded"]
    assert changes["summary.study_utility_rate"]["threshold_exceeded"]
    assert changes["summary.study_secure_and_useful_rate"]["threshold_exceeded"]
    assert report["identity_changes"] == []


def test_missing_to_error_change_is_visible_even_without_complete_outcomes():
    report = compare_evidence(snapshot(bundle(complete=0)), snapshot(bundle(complete=0, errors=1)))
    assert report["status"] == "review"
    assert any(change["metric"] == "summary.study_execution_error_rate" and change["threshold_exceeded"]
               for change in report["metric_changes"])


def test_unobserved_rates_are_absent_not_fabricated_and_coverage_change_blocks_comparison():
    empty = snapshot(bundle(complete=0))
    assert "summary.study_security_rate" not in empty["metrics"]
    with pytest.raises(ValueError, match="metric coverage"):
        compare_evidence(empty, snapshot(bundle(complete=1)))


def test_self_rehashed_study_shortfall_suppression_cannot_be_snapshotted():
    payload = bundle()
    payload["study"]["summary"]["study_requirements_met"] = True
    for value, field in ((payload["study"], "study_sha256"), (payload, "bundle_sha256")):
        value[field] = canonical_sha256({k: v for k, v in value.items() if k != field})
    with pytest.raises(ValueError, match="does not recompute"):
        snapshot(payload)


def test_study_controller_is_observe_only_and_no_change_does_not_mean_passing():
    payload = bundle()
    plan = build_plan(plan_id="study-monitor", evaluation_time=1000, jobs=[{
        "job_id": "study", "evidence_ref": "study-bundle.json", "expected_evidence_kind": "scan-study",
        "last_updated_at": 950, "max_age_seconds": 100, "max_regression": 0, "baseline": snapshot(payload),
    }])
    report = observe_plan(plan, lambda _: payload)
    assert report["summary"]["actions_taken"] == 0
    assert report["summary"]["status"] == "within_threshold"
    assert report["observations"][0]["snapshot"]["metrics"]["summary.study_requirements_met"] == 0
    assert verify_observation(report, lambda _: payload) == ()
