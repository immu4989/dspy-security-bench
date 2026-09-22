"""Successful process exit must not conceal unmet evidence requirements."""

import json

import pandas as pd
import pytest

from dspy_security_bench.scan.config import GateSpec
from dspy_security_bench.scan.gate import ScanReport, evaluate_gate
from dspy_security_bench.scan.report import render_json, render_sarif, render_terminal


@pytest.mark.parametrize("security,fail_on,expected", [
    (1.0, "error", "requirements_met"),
    (0.0, "error", "blocked"),
    (0.0, "never", "non_blocking_shortfalls"),
    (0.87, "error", "non_blocking_shortfalls"),
    (0.87, "warning", "blocked"),
])
def test_enforcement_and_requirements_remain_distinct_across_outputs(security, fail_on, expected):
    summary = pd.DataFrame([{
        "agent": "fixture", "defense": "none", "attack": "direct",
        "security_rate": security, "injection_success_rate": 1 - security,
        "n_runs": 100,
    }])
    report = evaluate_gate(summary, GateSpec(min_security=0.9), "workspace", fail_on=fail_on)
    payload = json.loads(render_json(report))
    assert payload["enforcement_status"] == expected
    assert payload["requirements_met"] is (security >= 0.9)
    assert payload["passed"] is (expected != "blocked")
    props = json.loads(render_sarif(report))["runs"][0]["properties"]
    assert props["enforcement_status"] == expected
    assert props["requirements_met"] == payload["requirements_met"]
    text = render_terminal(report, use_color=False)
    if expected == "non_blocking_shortfalls":
        assert "Verdict: PASS" not in text
        assert "NON-BLOCKING SHORTFALLS" in text
        assert "Requirements met: no" in text
    elif expected == "requirements_met":
        assert "Verdict: PASS" in text


def test_empty_api_report_never_claims_all_requirements_met():
    report = ScanReport(findings=[], passed=True, exit_code=0, mode="absolute")
    assert not report.requirements_met
    assert report.enforcement_status == "non_blocking_shortfalls"
