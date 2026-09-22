from __future__ import annotations

from copy import deepcopy

import pytest

from dspy_security_bench.collective.v2 import analyze_scenario_v2, built_in_scenario_v2
from dspy_security_bench.continuous.controller import (
    append_timeline,
    build_plan,
    observe_plan,
    verify_observation,
    verify_observation_envelope,
    verify_plan,
    verify_timeline,
)
from dspy_security_bench.continuous.proof import build_evidence_snapshot
from dspy_security_bench.mission.loader import canonical_sha256


def _report(profile="hardened-complete"):
    return analyze_scenario_v2(built_in_scenario_v2(profile))


def _plan(report, *, now=1000, updated=950):
    return build_plan(
        plan_id="daily-assurance",
        evaluation_time=now,
        jobs=[
            {
                "job_id": "collectiveguard",
                "evidence_ref": "collective.json",
                "expected_evidence_kind": "collective-v2",
                "last_updated_at": updated,
                "max_age_seconds": 100,
                "max_regression": 0.0,
                "baseline": build_evidence_snapshot(report, label="approved"),
            }
        ],
    )


def test_observe_only_controller_verifies_without_actions():
    evidence = _report()
    plan = _plan(evidence)
    assert verify_plan(plan) == ()
    observation = observe_plan(plan, lambda _: evidence)
    assert observation["summary"]["status"] == "within_threshold"
    assert observation["summary"]["actions_taken"] == 0
    assert verify_observation(observation, lambda _: evidence) == ()


def test_stale_or_missing_evidence_requires_review():
    evidence = _report()
    stale = observe_plan(_plan(evidence, now=2000), lambda _: evidence)
    assert stale["summary"]["status"] == "review_required"
    assert stale["summary"]["stale_count"] == 1

    missing = observe_plan(_plan(evidence), lambda _: (_ for _ in ()).throw(OSError("missing")))
    assert missing["summary"]["invalid_count"] == 1
    assert missing["summary"]["actions_taken"] == 0


def test_regression_is_detected_against_verified_baseline():
    baseline = _report()
    plan = _plan(baseline)
    observation = observe_plan(plan, lambda _: _report("emergent-complete"))
    assert observation["summary"]["status"] == "review_required"
    assert observation["summary"]["regression_count"] == 1


def test_timeline_is_append_only_and_tamper_evident():
    report = _report()
    first = observe_plan(_plan(report), lambda _: report)
    timeline = append_timeline(None, first, timeline_id="production-assurance")
    second = observe_plan(_plan(report, now=1050, updated=1040), lambda _: report)
    timeline = append_timeline(timeline, second, timeline_id="production-assurance")
    assert len(timeline["entries"]) == 2
    assert verify_timeline(timeline) == ()
    tampered = deepcopy(timeline)
    tampered["entries"][0]["observation"]["summary"]["status"] = "review_required"
    assert verify_timeline(tampered)
    with pytest.raises(ValueError, match="strictly increasing|already present"):
        append_timeline(timeline, second, timeline_id="production-assurance")


def _rehash(payload, field):
    payload.pop(field, None)
    payload[field] = canonical_sha256(payload)
    return payload


@pytest.mark.parametrize("mutation", ["summary", "job", "reference", "stale", "reasons", "status", "drift", "boolean-version", "boolean-actions"])
def test_rehashed_observation_lifecycle_tampering_is_rejected(mutation):
    evidence = _report()
    observation = observe_plan(_plan(evidence, now=2000), lambda _: evidence)
    row = observation["observations"][0]
    if mutation == "summary":
        observation["summary"]["status"] = "within_threshold"
    elif mutation == "job":
        row["job_id"] = "substitute"
    elif mutation == "reference":
        row["evidence_ref"] = "other.json"
    elif mutation == "stale":
        row["stale"] = False
    elif mutation == "reasons":
        row["reasons"] = []
    elif mutation == "status":
        row["status"] = "within_threshold"
    elif mutation == "drift":
        row["drift"] = None
    elif mutation == "boolean-version":
        observation["schema_version"] = True
    else:
        observation["summary"]["actions_taken"] = False
    _rehash(observation, "observation_sha256")
    assert verify_observation_envelope(observation)
    assert verify_observation(observation, lambda _: evidence)
    with pytest.raises(ValueError, match="invalid observation"):
        append_timeline(None, observation, timeline_id="test")


def test_future_dated_evidence_is_not_fresh():
    with pytest.raises(ValueError, match="later than evaluation_time"):
        _plan(_report(), now=1000, updated=1001)


@pytest.mark.parametrize("threshold", [float("nan"), float("inf"), True, 10**400])
def test_controller_rejects_nonfinite_or_boolean_threshold(threshold):
    plan = _plan(_report())
    plan["jobs"][0]["max_regression"] = threshold
    assert verify_plan(plan)


def test_invalid_evidence_diagnostics_do_not_retain_exception_payload():
    def fail(_):
        raise ValueError("private-record-content fictional-token")

    observation = observe_plan(_plan(_report()), fail)
    assert "private-record-content" not in str(observation)
    assert observation["summary"]["invalid_count"] == 1
    assert verify_observation_envelope(observation) == ()
    assert verify_observation(observation, fail) == ()


def test_timeline_time_cannot_be_relabelled_after_rehash():
    evidence = _report()
    observation = observe_plan(_plan(evidence), lambda _: evidence)
    timeline = append_timeline(None, observation, timeline_id="test")
    timeline["entries"][0]["observed_at"] += 1
    _rehash(timeline["entries"][0], "entry_sha256")
    _rehash(timeline, "timeline_sha256")
    assert any("evaluation time" in error for error in verify_timeline(timeline))


def test_boolean_sequence_cannot_alias_first_entry_after_rehash():
    evidence = _report()
    timeline = append_timeline(None, observe_plan(_plan(evidence), lambda _: evidence), timeline_id="test")
    timeline["entries"][0]["sequence"] = True
    _rehash(timeline["entries"][0], "entry_sha256")
    _rehash(timeline, "timeline_sha256")
    assert verify_timeline(timeline)
