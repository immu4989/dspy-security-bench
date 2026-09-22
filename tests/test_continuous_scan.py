"""Native scan evidence can join observe-only evidence reviews without model calls."""

import json
from copy import deepcopy

import pytest

from dspy_security_bench.continuous.controller import build_plan, observe_plan, verify_observation
from dspy_security_bench.continuous.proof import (
    build_evidence_snapshot,
    compare_evidence,
    verify_snapshot_source,
)
from dspy_security_bench.scan.config import GateSpec
from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.evidence import build_scan_evidence, evidence_policy


def evidence():
    return json.loads(build_demo_artifacts()["before.json"])


def test_scan_snapshots_use_native_replay_and_per_cell_metrics():
    source = evidence()
    snapshot = build_evidence_snapshot(source, label="reference")
    assert snapshot["evidence_kind"] == "scan"
    assert verify_snapshot_source(snapshot, source) == ()
    assert snapshot["metrics"]["summary.requirements_met"] == 0.0
    assert sorted(value for key, value in snapshot["metrics"].items() if key.endswith("security_rate")) == [4 / 6]
    assert sorted(value for key, value in snapshot["metrics"].items() if key.endswith("utility_rate")) == [5 / 6]
    assert "fictional" not in str(snapshot["metrics"])


def test_scan_security_and_utility_regressions_are_not_combined():
    source = evidence()
    rows = deepcopy(source["observations"])
    for row in rows:
        row.update(security=1, injection_succeeded=0, utility=0)
    candidate = build_scan_evidence(source["scope"], source["policy"], rows)
    drift = compare_evidence(build_evidence_snapshot(source, label="old"), build_evidence_snapshot(candidate, label="new"))
    assert drift["status"] == "review"
    assert any(item["metric"].endswith("utility_rate") and item["threshold_exceeded"] for item in drift["metric_changes"])
    assert not any(item["metric"].endswith("security_rate") and item["threshold_exceeded"] for item in drift["metric_changes"])


def test_self_rehashed_false_scan_verdict_cannot_be_snapshotted():
    source = evidence()
    source["report"]["requirements_met"] = True
    from dspy_security_bench.mission.loader import canonical_sha256

    source["evidence_sha256"] = canonical_sha256({key: value for key, value in source.items() if key != "evidence_sha256"})
    with pytest.raises(ValueError, match="does not recompute"):
        build_evidence_snapshot(source, label="tampered")


def test_utility_policy_change_and_protocol_upgrade_require_review():
    source = evidence()
    policy = evidence_policy(GateSpec(min_utility=0.8), "error")
    candidate = build_scan_evidence(source["scope"], policy, source["observations"])
    drift = compare_evidence(build_evidence_snapshot(source, label="old"), build_evidence_snapshot(candidate, label="new"))
    assert drift["status"] == "review"
    assert {item["field"] for item in drift["identity_changes"]} == {"scan_policy_sha256", "scan_protocol_version"}


def test_scan_controller_is_observe_only_and_recomputes():
    source = evidence()
    snapshot = build_evidence_snapshot(source, label="baseline")
    plan = build_plan(plan_id="scan-review", evaluation_time=1000, jobs=[{
        "job_id": "agent-scan", "evidence_ref": "scan.json", "expected_evidence_kind": "scan",
        "last_updated_at": 950, "max_age_seconds": 100, "max_regression": 0.0, "baseline": snapshot,
    }])
    report = observe_plan(plan, lambda _: source)
    assert report["summary"]["actions_taken"] == 0
    assert report["summary"]["status"] == "within_threshold"
    # No-change status is deliberately not evidence that original requirements passed.
    assert report["observations"][0]["snapshot"]["metrics"]["summary.requirements_met"] == 0.0
    assert verify_observation(report, lambda _: source) == ()
