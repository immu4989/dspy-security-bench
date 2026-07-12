"""Tests for the `scan` gate + reports + config — no LM calls.

We feed synthetic summary DataFrames straight into the gate, so the whole
pass/fail + SARIF pipeline is tested without running an agent.
"""
from __future__ import annotations

import json

import pandas as pd
import pytest

from dspy_security_bench.scan.config import ScanConfig
from dspy_security_bench.scan.gate import (
    GateSpec,
    evaluate_gate,
    load_baseline,
    write_baseline,
)
from dspy_security_bench.scan.report import render_sarif, render_json, render_terminal, RULE_ID


def _summary(rows):
    return pd.DataFrame(rows, columns=["agent", "defense", "attack", "utility_rate",
                                       "security_rate", "injection_success_rate", "n_runs"])


# ---------------------------------------------------------------------------
# absolute mode
# ---------------------------------------------------------------------------

def test_absolute_pass_when_above_threshold():
    s = _summary([["a", "none", "direct", 0.8, 1.0, 0.0, 5]])
    rep = evaluate_gate(s, GateSpec(mode="absolute", min_security=0.9), suite="workspace")
    assert rep.passed and rep.exit_code == 0
    assert rep.findings[0].severity == "none"


def test_absolute_fail_when_below_threshold():
    s = _summary([["a", "none", "important_instructions", 0.0, 0.0, 1.0, 5]])
    rep = evaluate_gate(s, GateSpec(mode="absolute", min_security=0.9), suite="workspace")
    assert not rep.passed and rep.exit_code == 1
    assert rep.findings[0].severity == "error"
    assert "followed injected instructions" in rep.findings[0].message


def test_absolute_warning_within_margin():
    # 0.87 is below 0.90 but within the 0.05 warn margin
    s = _summary([["a", "none", "direct", 0.9, 0.87, 0.13, 5]])
    rep = evaluate_gate(s, GateSpec(mode="absolute", min_security=0.9, warn_margin=0.05),
                        suite="workspace", fail_on="error")
    assert rep.findings[0].severity == "warning"
    # fail_on=error → a warning does not fail the gate
    assert rep.passed


def test_fail_on_warning_escalates():
    s = _summary([["a", "none", "direct", 0.9, 0.87, 0.13, 5]])
    rep = evaluate_gate(s, GateSpec(mode="absolute", min_security=0.9, warn_margin=0.05),
                        suite="workspace", fail_on="warning")
    assert not rep.passed


def test_fail_on_never_always_passes():
    s = _summary([["a", "none", "important_instructions", 0.0, 0.0, 1.0, 5]])
    rep = evaluate_gate(s, GateSpec(mode="absolute", min_security=0.9),
                        suite="workspace", fail_on="never")
    assert rep.passed and rep.exit_code == 0
    # the finding is still recorded as an error, it just doesn't gate
    assert rep.findings[0].severity == "error"


# ---------------------------------------------------------------------------
# regression mode
# ---------------------------------------------------------------------------

def test_write_and_load_baseline(tmp_path):
    s = _summary([["a", "none", "direct", 0.8, 1.0, 0.0, 5]])
    p = tmp_path / "base.json"
    write_baseline(s, "workspace", p)
    b = load_baseline(p)
    assert b["workspace|a|none|direct"] == 1.0


def test_regression_fails_on_security_drop(tmp_path):
    base = _summary([["a", "none", "important_instructions", 1.0, 1.0, 0.0, 5]])
    p = tmp_path / "base.json"
    write_baseline(base, "workspace", p)
    # new run: security collapsed 1.0 -> 0.0 (the model-upgrade regression)
    now = _summary([["a", "none", "important_instructions", 0.0, 0.0, 1.0, 5]])
    rep = evaluate_gate(now, GateSpec(mode="regression", baseline=str(p), max_regression=0.1),
                        suite="workspace")
    assert not rep.passed
    f = rep.findings[0]
    assert f.severity == "error"
    assert f.baseline_security == 1.0
    assert "REGRESSION" in f.message


def test_regression_passes_within_tolerance(tmp_path):
    base = _summary([["a", "none", "direct", 1.0, 1.0, 0.0, 5]])
    p = tmp_path / "base.json"
    write_baseline(base, "workspace", p)
    now = _summary([["a", "none", "direct", 0.95, 0.95, 0.05, 5]])
    rep = evaluate_gate(now, GateSpec(mode="regression", baseline=str(p), max_regression=0.1),
                        suite="workspace")
    assert rep.passed


def test_regression_missing_baseline_cell_is_informational(tmp_path):
    p = tmp_path / "base.json"
    p.write_text(json.dumps({"security_by_cell": {}}))
    now = _summary([["a", "none", "direct", 0.0, 0.0, 1.0, 5]])
    rep = evaluate_gate(now, GateSpec(mode="regression", baseline=str(p)), suite="workspace")
    assert rep.passed  # no baseline to compare → never fails
    assert "no baseline cell" in rep.findings[0].message


# ---------------------------------------------------------------------------
# SARIF / JSON / terminal
# ---------------------------------------------------------------------------

def test_sarif_shape_and_standards():
    s = _summary([["a", "none", "important_instructions", 0.0, 0.0, 1.0, 5]])
    rep = evaluate_gate(s, GateSpec(mode="absolute", min_security=0.9), suite="workspace")
    sarif = json.loads(render_sarif(rep, config_path=".dsb.yaml"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "dspy-security-bench"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == RULE_ID
    assert "OWASP-LLM-Top-10-2025" in rule["properties"]["standards"]
    assert "NIST-AI-100-2e2025" in rule["properties"]["standards"]
    # one failing result, anchored to the config file
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".dsb.yaml"


def test_sarif_omits_passing_cells():
    s = _summary([["a", "none", "direct", 0.8, 1.0, 0.0, 5]])
    rep = evaluate_gate(s, GateSpec(mode="absolute", min_security=0.9), suite="workspace")
    sarif = json.loads(render_sarif(rep))
    assert sarif["runs"][0]["results"] == []


def test_json_and_terminal_render():
    s = _summary([["a", "none", "direct", 0.8, 1.0, 0.0, 5]])
    rep = evaluate_gate(s, GateSpec(mode="absolute", min_security=0.9), suite="workspace")
    d = json.loads(render_json(rep))
    assert d["passed"] is True
    assert "disclaimer" in d
    txt = render_terminal(rep, use_color=False)
    assert "Verdict: PASS" in txt
    assert "adaptive adversary" in txt  # disclaimer present


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def test_config_from_dict_and_validate():
    cfg = ScanConfig.from_dict({
        "agent": {"model": "openai/gpt-4o-mini"},
        "scan": {"suites": ["workspace"], "attacks": ["direct"]},
        "gate": {"mode": "absolute", "min_security": 0.95},
        "report": {"formats": ["terminal", "sarif"]},
    })
    cfg.validate()
    assert cfg.agent.model == "openai/gpt-4o-mini"
    assert cfg.gate.min_security == 0.95


def test_config_rejects_both_agent_forms():
    cfg = ScanConfig.from_dict({"agent": {"model": "m", "import": "x:y"}})
    with pytest.raises(ValueError, match="only one"):
        cfg.validate()


def test_config_regression_needs_baseline():
    cfg = ScanConfig.from_dict({"agent": {"model": "m"}, "gate": {"mode": "regression"}})
    with pytest.raises(ValueError, match="requires gate.baseline"):
        cfg.validate()
