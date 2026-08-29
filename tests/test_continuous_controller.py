from __future__ import annotations

from copy import deepcopy

import pytest

from dspy_security_bench.collective.v2 import analyze_scenario_v2, built_in_scenario_v2
from dspy_security_bench.continuous.controller import (
    append_timeline,
    build_plan,
    observe_plan,
    verify_observation,
    verify_plan,
    verify_timeline,
)
from dspy_security_bench.continuous.proof import build_evidence_snapshot


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
