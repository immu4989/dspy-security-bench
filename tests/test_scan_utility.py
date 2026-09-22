"""Resistance cannot compensate for a separately required task-utility floor."""

import json
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pandas as pd
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.config import GateSpec, ScanConfig
from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.evidence import (
    build_scan_evidence,
    evidence_policy,
    verify_scan_evidence,
)
from dspy_security_bench.scan.gate import evaluate_gate
from dspy_security_bench.scan.report import UTILITY_RULE_ID, render_sarif, render_terminal


def summary(utility=0.0):
    return pd.DataFrame([{"agent": "refusal", "defense": "none", "attack": "direct",
                          "security_rate": 1.0, "injection_success_rate": 0.0,
                          "n_runs": 5, "security_successes": 5, "utility_rate": utility}])


def test_refusal_like_outcomes_fail_only_the_separate_utility_requirement():
    report = evaluate_gate(summary(), GateSpec(min_utility=0.8), "fixture")
    assert report.findings[0].passed
    assert not report.requirements_met and report.exit_code == 1
    assert report.findings[1].finding_type == "utility_threshold"
    assert report.findings[1].utility_rate == 0.0
    sarif = json.loads(render_sarif(report))["runs"][0]["results"]
    assert len(sarif) == 1 and sarif[0]["ruleId"] == UTILITY_RULE_ID
    assert "task utility under attack=0.00%" in render_terminal(report, use_color=False)


def test_utility_is_opt_in_and_nonblocking_policy_does_not_erase_failure():
    assert evaluate_gate(summary(), GateSpec(), "fixture").requirements_met
    report = evaluate_gate(summary(), GateSpec(min_utility=0.8), "fixture", fail_on="never")
    assert report.passed and report.exit_code == 0
    assert not report.requirements_met
    assert report.enforcement_status == "non_blocking_shortfalls"


def test_utility_floor_is_inclusive_and_not_downgraded_by_security_warn_margin():
    assert evaluate_gate(summary(0.8), GateSpec(min_utility=0.8), "fixture").requirements_met
    report = evaluate_gate(summary(0.79), GateSpec(min_utility=0.8, warn_margin=1.0), "fixture")
    assert report.exit_code == 1 and report.findings[-1].severity == "error"


@pytest.mark.parametrize("value", [True, -0.1, 1.1, float("nan"), float("inf"), "0.8"])
def test_invalid_utility_policy_or_measurement_is_rejected(value):
    with pytest.raises(ValueError, match="min_utility"):
        GateSpec(min_utility=value).validate()
    with pytest.raises(ValueError, match="utility_rate"):
        evaluate_gate(summary(value), GateSpec(min_utility=0.8), "fixture")


def test_missing_utility_measurement_is_not_assumed_success():
    with pytest.raises(ValueError, match="measured utility_rate"):
        evaluate_gate(summary().drop(columns=["utility_rate"]), GateSpec(min_utility=0.8), "fixture")


def test_security_wilson_and_utility_point_floor_remain_separate():
    report = evaluate_gate(summary(1.0), GateSpec(min_security=0.9, statistic="wilson_lower", min_utility=0.8), "fixture")
    assert not report.findings[0].passed
    assert report.findings[-1].passed and report.findings[-1].security_lower is None


def test_utility_floor_applies_alongside_security_regression(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"security_by_cell": {"fixture|refusal|none|direct": 1.0}}))
    report = evaluate_gate(summary(), GateSpec(mode="regression", baseline=str(baseline), min_utility=0.8), "fixture")
    assert report.findings[0].passed and not report.findings[-1].passed


def test_v1_replay_contract_remains_byte_identical():
    payload = json.loads(build_demo_artifacts()["before.json"])
    assert payload["evidence_sha256"] == "97a3a3e2829521256199a1b78a9a4bedde39f2a8686693a02691d7059f3c20cd"
    assert payload["protocol_version"] == "scan-evidence-v1"
    verify_scan_evidence(payload)


def test_v2_utility_evidence_replays_and_rejects_rehashed_missing_finding():
    legacy = json.loads(build_demo_artifacts()["before.json"])
    policy = evidence_policy(GateSpec(min_security=0.0, min_utility=0.9), "error")
    payload = build_scan_evidence(legacy["scope"], policy, legacy["observations"])
    assert payload["schema_version"] == 2 and payload["protocol_version"] == "scan-evidence-v2"
    assert not verify_scan_evidence(payload)["requirements_met"]
    schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-evidence.schema.json").read_text())
    jsonschema.validate(payload, schema)
    tampered = deepcopy(payload)
    tampered["report"]["findings"].pop()
    tampered["evidence_sha256"] = canonical_sha256({key: value for key, value in tampered.items() if key != "evidence_sha256"})
    with pytest.raises(ValueError, match="exactly recompute"):
        verify_scan_evidence(tampered)
    for field, value in (("schema_version", 1), ("protocol_version", "scan-evidence-v1")):
        wrong = {**payload, field: value}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(wrong, schema)
        with pytest.raises(ValueError, match="exactly recompute"):
            verify_scan_evidence(wrong)


def test_config_and_plan_pin_include_utility_requirement(tmp_path, monkeypatch):
    cfg = ScanConfig.from_dict({"agent": {"model": "fixture"}, "gate": {"min_utility": 0.8}})
    cfg.validate()
    assert cfg.gate.min_utility == 0.8
    first = tmp_path / "plan.json"
    args = ["--agent-model", "fixture", "--min-utility", "0.8"]
    assert main([*args, "--plan-json", str(first)]) == 0
    plan = json.loads(first.read_text())
    assert plan["gate"]["min_utility"] == 0.8

    def forbidden(*args, **kwargs):
        pytest.fail("changed utility policy must not construct an agent")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    assert main(["--agent-model", "fixture", "--min-utility", "0.7", "--expected-plan-sha256", plan["report_sha256"]]) == 2


def test_scan_capture_replays_the_same_utility_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda *args: object())
    rows = pd.DataFrame([{"agent": "fixture", "defense": "none", "attack": "direct",
                          "user_task_id": "user_task_0", "injection_task_id": "injection_task_0",
                          "utility": 0, "security": 1, "injection_succeeded": 0}])
    monkeypatch.setattr("dspy_security_bench.runner.evaluate_agents", lambda **kwargs: rows)
    evidence = tmp_path / "capture.json"
    report = tmp_path / "report.json"
    assert main(["--agent-model", "fixture", "--attacks", "direct", "--user-tasks", "1",
                 "--injection-tasks", "1", "--min-utility", "0.8",
                 "--evidence-json", str(evidence), "--json", str(report)]) == 1
    captured = json.loads(evidence.read_text())
    assert captured["protocol_version"] == "scan-evidence-v2"
    assert captured["report"] == json.loads(report.read_text())
    assert main(["verify", str(evidence), "--fail-on-shortfalls"]) == 1
