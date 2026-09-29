"""Marginal success is not same-task secure and useful success."""
import json
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pandas as pd
import pytest

from dspy_security_bench.continuous.proof import build_evidence_snapshot, compare_evidence
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.runner import summarize
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.config import GateSpec, ScanConfig
from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.evidence import (
    build_scan_evidence,
    evidence_policy,
    verify_scan_evidence,
)
from dspy_security_bench.scan.gate import evaluate_gate
from dspy_security_bench.scan.report import JOINT_RULE_ID, render_sarif, render_terminal
from dspy_security_bench.scan.study import build_study_plan
from dspy_security_bench.scan.study_bundle import build_study_bundle, verify_study_bundle


def frame():
    return pd.DataFrame([{"agent": "fixture", "defense": "none", "attack": "direct",
                         "security": s, "utility": u, "injection_succeeded": 1 - s}
                        for s, u in ((1, 1), (1, 1), (1, 1), (1, 0), (0, 1))])


def evidence(min_utility=None):
    old = json.loads(build_demo_artifacts()["before.json"])
    rows = deepcopy(old["observations"])
    for i, row in enumerate(rows):
        row.update(security=int(i != 5), injection_succeeded=int(i == 5), utility=int(i != 4))
    policy = evidence_policy(GateSpec(min_security=0.8, min_utility=min_utility, min_joint_success=0.75), "error")
    return build_scan_evidence(old["scope"], policy, rows)


def test_equal_marginals_do_not_mask_disjoint_successes():
    original = frame()
    summary = summarize(original)
    assert "_joint_success" not in original.columns
    assert summary.iloc[0]["security_rate"] == summary.iloc[0]["utility_rate"] == 0.8
    assert summary.iloc[0]["joint_success_rate"] == 0.6
    assert summary.iloc[0]["joint_successes"] == 3
    assert evaluate_gate(summary, GateSpec(min_security=0.8, min_utility=0.8), "fixture").requirements_met
    report = evaluate_gate(summary, GateSpec(min_security=0.8, min_utility=0.8, min_joint_success=0.7), "fixture")
    assert report.exit_code == 1 and not report.requirements_met
    assert [f.passed for f in report.findings] == [True, True, False]
    assert report.findings[-1].joint_successes == 3
    assert "secure AND useful=3/5 (60.00%)" in render_terminal(report, use_color=False)
    results = json.loads(render_sarif(report))["runs"][0]["results"]
    assert len(results) == 1 and results[0]["ruleId"] == JOINT_RULE_ID
    assert results[0]["properties"]["joint_successes"] == 3


def test_joint_floor_is_inclusive_and_not_softened_by_security_warning_margin():
    summary = summarize(frame())
    assert evaluate_gate(summary, GateSpec(min_security=0.8, min_joint_success=0.6), "fixture").requirements_met
    report = evaluate_gate(summary, GateSpec(min_security=0.8, min_joint_success=0.61, warn_margin=1), "fixture")
    assert report.findings[-1].severity == "error"
    assert report.exit_code == 1


def test_nonblocking_enforcement_preserves_joint_shortfall():
    report = evaluate_gate(summarize(frame()), GateSpec(min_security=0.8, min_joint_success=0.7), "fixture", "never")
    assert report.exit_code == 0 and report.enforcement_status == "non_blocking_shortfalls"
    assert not report.requirements_met


@pytest.mark.parametrize("value", [True, -1, 1.1, float("nan"), float("inf"), "0.7"])
def test_joint_floor_is_strictly_typed_and_finite(value):
    with pytest.raises(ValueError, match="min_joint_success"):
        GateSpec(min_joint_success=value).validate()


@pytest.mark.parametrize("column", ["security_successes", "utility_successes", "utility_rate", "joint_successes", "joint_success_rate"])
def test_missing_joint_measurements_are_not_inferred_from_marginals(column):
    with pytest.raises(ValueError, match="requires measured"):
        evaluate_gate(summarize(frame()).drop(columns=[column]), GateSpec(min_joint_success=0.5), "fixture")


@pytest.mark.parametrize("joint,utility,rate", [(2, 4, 0.4), (5, 4, 1.0), (-1, 4, 0),
    (3.5, 4, 0.7), (3, 4.5, 0.6), (3, 4, 0.8), (float("nan"), 4, 0.6)])
def test_inconsistent_counts_or_rates_are_rejected(joint, utility, rate):
    summary = summarize(frame()).astype(object)
    summary.loc[0, "joint_successes"] = joint
    summary.loc[0, "joint_success_rate"] = rate
    summary.loc[0, "utility_successes"] = utility
    with pytest.raises(ValueError):
        evaluate_gate(summary, GateSpec(min_joint_success=0.5), "fixture")


def test_joint_point_gate_is_distinct_from_security_wilson_bound():
    report = evaluate_gate(summarize(frame()), GateSpec(min_security=0.8, statistic="wilson_lower", min_joint_success=0.6), "fixture")
    assert not report.findings[0].passed
    assert report.findings[-1].passed and report.findings[-1].security_lower is None


def test_joint_floor_applies_alongside_security_regression(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"security_by_cell": {"fixture|fixture|none|direct": 0.8}}))
    report = evaluate_gate(summarize(frame()), GateSpec(mode="regression", baseline=str(baseline),
                           min_joint_success=0.7), "fixture")
    assert report.findings[0].passed and not report.findings[-1].passed


@pytest.mark.parametrize("column", ["utility_successes", "joint_successes"])
def test_boolean_counts_cannot_masquerade_as_measurements(column):
    summary = summarize(frame()).astype(object)
    summary.loc[0, column] = True
    with pytest.raises(ValueError, match="integer"):
        evaluate_gate(summary, GateSpec(min_joint_success=0.0), "fixture")


@pytest.mark.parametrize("utility", [None, 0.8])
def test_v3_round_trip_schema_and_rehashed_joint_tamper_rejection(utility):
    payload = evidence(utility)
    assert payload["schema_version"] == 3 and payload["protocol_version"] == "scan-evidence-v3"
    assert not verify_scan_evidence(payload)["requirements_met"]
    schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-evidence.schema.json").read_text())
    jsonschema.validate(payload, schema)
    false = deepcopy(payload)
    false["report"]["findings"][-1].update(passed=True, severity="none", joint_successes=6)
    false["evidence_sha256"] = canonical_sha256({k: v for k, v in false.items() if k != "evidence_sha256"})
    with pytest.raises(ValueError, match="recompute"):
        verify_scan_evidence(false)
    for version in (1, 2):
        false = {**payload, "schema_version": version, "protocol_version": f"scan-evidence-v{version}"}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(false, schema)
        with pytest.raises(ValueError):
            verify_scan_evidence(false)


def test_explicit_null_joint_policy_is_not_a_legacy_alias():
    payload = evidence()
    payload["policy"]["min_joint_success"] = None
    with pytest.raises(ValueError, match="numeric floor"):
        verify_scan_evidence(payload)


def test_joint_evidence_integrates_with_study_bundles():
    payload = evidence()
    plan = build_study_plan(payload, "joint-study", 2)
    trials = [{"trial_id": name, "status": "complete", "evidence_sha256": payload["evidence_sha256"]} for name in plan["trial_ids"]]
    bundled = build_study_bundle(plan, trials, dict.fromkeys(plan["trial_ids"], payload))
    assert verify_study_bundle(bundled)["secure_and_useful"]["observed_rate"] == 4 / 6
    assert not verify_study_bundle(bundled)["study_requirements_met"]


def test_same_marginals_with_lower_joint_success_trigger_drift():
    after = evidence()
    rows = deepcopy(after["observations"])
    rows[4]["utility"], rows[5]["utility"] = 1, 0
    before = build_scan_evidence(after["scope"], after["policy"], rows)
    report = compare_evidence(build_evidence_snapshot(before, label="old"), build_evidence_snapshot(after, label="new"))
    assert report["status"] == "review"
    joint = [c for c in report["metric_changes"] if c["metric"].endswith("joint_success_rate")]
    assert len(joint) == 1 and joint[0]["threshold_exceeded"]
    assert joint[0]["direction"] == "higher_is_better"


def test_joint_policy_is_pinned_before_agent_construction(tmp_path, monkeypatch):
    cfg = ScanConfig.from_dict({"agent": {"model": "fixture"}, "gate": {"min_joint_success": 0.7}})
    cfg.validate()
    assert cfg.gate.min_joint_success == 0.7
    plan_path = tmp_path / "plan.json"
    assert main(["--agent-model", "fixture", "--min-joint-success", "0.7", "--plan-json", str(plan_path)]) == 0
    plan = json.loads(plan_path.read_text())
    assert plan["gate"]["min_joint_success"] == 0.7

    def forbidden(*args, **kwargs):
        pytest.fail("joint policy mismatch reached agent construction")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    assert main(["--agent-model", "fixture", "--min-joint-success", "0.8",
                 "--expected-plan-sha256", plan["report_sha256"]]) == 2


def test_live_mocked_scan_matches_native_replay_for_joint_gate(tmp_path, monkeypatch):
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda *a: object())
    row = {"agent": "fixture", "defense": "none", "attack": "direct", "user_task_id": "user_task_0",
           "injection_task_id": "injection_task_0", "utility": 0, "security": 1, "injection_succeeded": 0}
    monkeypatch.setattr("dspy_security_bench.runner.evaluate_agents", lambda **kw: pd.DataFrame([row]))
    capture, report = tmp_path / "capture.json", tmp_path / "report.json"
    assert main(["--agent-model", "fixture", "--attacks", "direct", "--user-tasks", "1",
                 "--injection-tasks", "1", "--min-joint-success", "0.8",
                 "--evidence-json", str(capture), "--json", str(report)]) == 1
    payload = json.loads(capture.read_text())
    assert verify_scan_evidence(payload) == json.loads(report.read_text())
    assert main(["verify", str(capture), "--fail-on-shortfalls"]) == 1
