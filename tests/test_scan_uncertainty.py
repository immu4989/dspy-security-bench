"""Count-backed uncertainty gates remain distinct from observed attack outcomes."""

import json

import pandas as pd
import pytest

from dspy_security_bench.scan.cli import build_gate_feasibility, main
from dspy_security_bench.scan.config import GateSpec, ScanConfig
from dspy_security_bench.scan.gate import evaluate_gate
from dspy_security_bench.scan.report import (
    SAMPLE_RULE_ID,
    UNCERTAINTY_RULE_ID,
    render_sarif,
    render_terminal,
)


def measured(successes, observations):
    return pd.DataFrame([{
        "agent": "fixture", "defense": "none", "attack": "direct",
        "security_rate": successes / observations,
        "injection_success_rate": 1 - successes / observations,
        "n_runs": observations, "security_successes": successes,
    }])


def test_five_of_five_does_not_establish_a_ninety_percent_lower_bound():
    report = evaluate_gate(measured(5, 5), GateSpec(statistic="wilson_lower"), "workspace")
    finding = report.findings[0]
    assert not report.passed
    assert finding.security_rate == 1
    assert finding.security_lower == pytest.approx(0.5655175352168252)
    assert finding.security_upper == 1
    assert finding.finding_type == "uncertainty_threshold"
    assert finding.severity == "error"
    assert "does not itself establish" in finding.message
    assert "multiple comparisons" in report.meta["uncertainty_boundary"]
    result = json.loads(render_sarif(report))["runs"][0]["results"][0]
    assert result["ruleId"] == UNCERTAINTY_RULE_ID
    assert "95.00% Wilson" in render_terminal(report, use_color=False)


@pytest.mark.parametrize("successes,n,lower,upper", [
    (0, 5, 0.0, 0.43448246478317476),
    (50, 100, 0.4038315303659956, 0.5961684696340044),
    (100, 100, 0.9630065017930143, 1.0),
])
def test_reference_two_sided_wilson_endpoints(successes, n, lower, upper):
    report = evaluate_gate(measured(successes, n), GateSpec(statistic="wilson_lower"), "workspace")
    assert report.findings[0].security_lower == pytest.approx(lower)
    assert report.findings[0].security_upper == pytest.approx(upper)


def test_minimum_sample_is_separate_from_attack_threshold():
    report = evaluate_gate(measured(5, 5), GateSpec(min_runs=20), "workspace")
    assert report.findings[0].passed
    assert not report.passed
    sample = report.findings[1]
    assert sample.finding_type == "sample_coverage"
    assert sample.required_runs == 20 and sample.threshold is None
    assert json.loads(render_sarif(report))["runs"][0]["results"][0]["ruleId"] == SAMPLE_RULE_ID


def test_minimum_sample_also_applies_to_regression(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"security_by_cell": {"workspace|fixture|none|direct": 1.0}}))
    gate = GateSpec(mode="regression", baseline=str(baseline), min_runs=10)
    assert not evaluate_gate(measured(5, 5), gate, "workspace").passed


def test_never_enforcement_preserves_the_shortfalls():
    report = evaluate_gate(measured(5, 5), GateSpec(min_runs=20, statistic="wilson_lower"), "workspace", fail_on="never")
    assert report.passed and report.exit_code == 0
    assert len(report.findings) == 2
    assert all(not f.passed and f.severity == "error" for f in report.findings)


def test_wilson_rejects_rate_only_summaries():
    with pytest.raises(ValueError, match="integer security_successes"):
        evaluate_gate(measured(5, 5).drop(columns="security_successes"), GateSpec(statistic="wilson_lower"), "workspace")


@pytest.mark.parametrize("field,value", [
    ("security_successes", -1), ("security_successes", 6),
    ("security_successes", 4), ("security_successes", 4.5),
    ("security_successes", True), ("security_successes", float("nan")),
    ("injection_success_rate", 0.5),
])
def test_inconsistent_counts_or_rates_are_invalid(field, value):
    summary = measured(5, 5).astype(object)
    summary.loc[0, field] = value
    with pytest.raises(ValueError):
        evaluate_gate(summary, GateSpec(statistic="wilson_lower"), "workspace")


@pytest.mark.parametrize("settings", [
    {"min_runs": 0}, {"min_runs": True}, {"min_runs": 1.5}, {"min_runs": 1_000_001},
    {"statistic": "wald"}, {"confidence": True}, {"confidence": 1.0},
    {"confidence": 0.49}, {"confidence": float("nan")},
    {"mode": "regression", "baseline": "base.json", "statistic": "wilson_lower"},
])
def test_invalid_uncertainty_settings_fail_before_execution(settings):
    cfg = ScanConfig.from_dict({"agent": {"model": "fixture"}, "gate": settings})
    with pytest.raises(ValueError):
        cfg.validate()


def test_plan_exposes_count_and_uncertainty_policy_without_building_agent(tmp_path, monkeypatch):
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda _: pytest.fail("must not build"))
    output = tmp_path / "plan.json"
    assert main(["--agent-model", "fixture", "--min-runs", "50", "--statistic", "wilson_lower",
                 "--confidence", "0.99", "--plan-json", str(output)]) == 0
    plan = json.loads(output.read_text())
    assert plan["gate"]["min_runs"] == 50
    assert plan["gate"]["statistic"] == "wilson_lower"
    assert plan["gate"]["confidence"] == 0.99
    assert plan["summary"]["model_calls_performed"] == 0
    assert not plan["gate_feasibility"]["all_cells_feasible"]


@pytest.mark.parametrize("args", [["--min-runs", "50"], ["--statistic", "wilson_lower"]])
def test_impossible_scopes_do_not_build_or_call_an_agent(monkeypatch, args):
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda _: pytest.fail("must not build"))
    assert main(["--agent-model", "fixture", *args]) == 2


@pytest.mark.parametrize("observations,possible", [(34, False), (35, True)])
def test_best_case_wilson_boundary_is_computed_per_cell(observations, possible):
    cfg = ScanConfig.from_dict({"agent": {"model": "fixture"},
                               "scan": {"defenses": ["none", "spotlighting"]},
                               "gate": {"statistic": "wilson_lower"}})
    plan = [{"suite": "fixture", "user_tasks": observations,
             "attack_cases": [{"attack": "direct", "injection_tasks": 1}]}]
    result = build_gate_feasibility(cfg, plan)
    assert result["all_cells_feasible"] is possible
    assert len(result["cells"]) == 2
    assert all(cell["planned_observations"] == observations for cell in result["cells"])


def test_extreme_uncertainty_counts_fail_as_invalid_evidence():
    with pytest.raises(ValueError, match="billion"):
        evaluate_gate(measured(10**12, 10**12), GateSpec(statistic="wilson_lower"), "workspace")


def test_runner_keeps_integer_security_counts():
    from dspy_security_bench.runner import summarize

    rows = pd.DataFrame([
        {"agent": "fixture", "defense": "none", "attack": "direct", "utility": 1,
         "security": success, "injection_succeeded": 1 - success}
        for success in (1, 0, 1)
    ])
    summary = summarize(rows)
    assert summary.iloc[0]["security_successes"] == 2
    assert summary.iloc[0]["n_runs"] == 3
    assert not evaluate_gate(summary, GateSpec(statistic="wilson_lower"), "workspace").passed
