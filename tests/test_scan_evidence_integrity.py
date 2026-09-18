import json

import pandas as pd
import pytest

from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.config import GateSpec, ScanConfig
from dspy_security_bench.scan.gate import evaluate_gate, load_baseline, write_baseline
from dspy_security_bench.scan.report import COVERAGE_RULE_ID, render_json, render_sarif


def summary():
    return pd.DataFrame(
        [
            {
                "agent": "agent-a",
                "defense": "none",
                "attack": "direct",
                "security_rate": 1.0,
                "injection_success_rate": 0.0,
                "n_runs": 5,
            }
        ]
    )


def test_missing_baseline_is_a_distinct_gap_not_a_pass_or_injection_success(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text('{"security_by_cell":{}}')
    result = evaluate_gate(summary(), GateSpec(mode="regression", baseline=str(path)), "workspace")
    assert result.passed is False
    assert result.exit_code == 1
    assert result.findings[0].finding_type == "baseline_coverage"
    assert result.findings[0].threshold is None
    assert result.meta["baseline_cells_missing"] == 1
    encoded = render_json(result)
    assert "NaN" not in encoded
    assert json.loads(encoded)["findings"][0]["threshold"] is None
    sarif = json.loads(render_sarif(result))
    assert sarif["runs"][0]["results"][0]["ruleId"] == COVERAGE_RULE_ID
    assert (
        "prompt injection succeeded"
        in sarif["runs"][0]["tool"]["driver"]["rules"][1]["fullDescription"]["text"]
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("security_rate", float("nan")),
        ("security_rate", float("inf")),
        ("security_rate", -0.1),
        ("security_rate", 1.1),
        ("security_rate", True),
        ("security_rate", "1.0"),
        ("injection_success_rate", float("nan")),
        ("n_runs", 0),
        ("n_runs", -1),
        ("n_runs", 1.5),
        ("n_runs", float("inf")),
        ("n_runs", True),
        ("agent", ""),
        ("agent", "a|b"),
        ("attack", None),
    ],
)
def test_invalid_summary_cannot_gate_or_become_baseline(tmp_path, field, value):
    data = summary().astype(object)
    data.at[0, field] = value
    with pytest.raises(ValueError):
        evaluate_gate(data, GateSpec(), "workspace", fail_on="never")
    with pytest.raises(ValueError):
        write_baseline(data, "workspace", tmp_path / "baseline.json")
    assert not (tmp_path / "baseline.json").exists()


@pytest.mark.parametrize("kind", ["empty", "missing-columns", "duplicate"])
def test_empty_or_ambiguous_measurement_is_not_a_success(kind):
    data = summary()
    if kind == "empty":
        data = data.iloc[:0]
    elif kind == "missing-columns":
        data = data.drop(columns=["n_runs"])
    else:
        data = pd.concat([data, data], ignore_index=True)
    with pytest.raises(ValueError):
        evaluate_gate(data, GateSpec(), "workspace")


@pytest.mark.parametrize(
    "raw",
    [
        "{}",
        '{"security_by_cell":[]}',
        '{"security_by_cell":{"a|b|c|d":1,"a|b|c|d":0}}',
        '{"security_by_cell":{"a|b|c|d":NaN}}',
        '{"security_by_cell":{"a|b|c|d":true}}',
        '{"security_by_cell":{"a|b|c|d":1.1}}',
        '{"security_by_cell":{"a|b|c|d":"1"}}',
        '{"security_by_cell":{"a|b|c":1}}',
        '{"security_by_cell":{"a||c|d":1}}',
    ],
)
def test_baselines_require_unambiguous_bounded_rates(tmp_path, raw):
    path = tmp_path / "baseline.json"
    path.write_text(raw)
    with pytest.raises(ValueError):
        load_baseline(path)


@pytest.mark.parametrize("value", [True, "0.9", float("nan"), float("inf"), -0.1, 1.1])
def test_gate_thresholds_validate_for_direct_api_and_config(value):
    with pytest.raises(ValueError):
        evaluate_gate(summary(), GateSpec(min_security=value), "workspace")
    config = ScanConfig.from_dict({"agent": {"model": "fixture"}, "gate": {"min_security": value}})
    with pytest.raises(ValueError):
        config.validate()


def test_bad_baseline_fails_cli_before_planning_or_agent_invocation(tmp_path, monkeypatch, capsys):
    path = tmp_path / "baseline.json"
    path.write_text('{"security_by_cell":{"a|b|c|d":NaN}}')

    def forbidden(*args, **kwargs):
        pytest.fail("invalid baseline must not start planning or invoke an agent")

    monkeypatch.setattr("dspy_security_bench.scan.cli.build_scan_plan", forbidden)
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    assert main(["--agent-model", "fixture", "--baseline", str(path)]) == 2
    assert "config error" in capsys.readouterr().err


def test_coverage_opt_out_requires_a_real_boolean():
    config = ScanConfig.from_dict(
        {"agent": {"model": "fixture"}, "gate": {"require_baseline_coverage": "false"}}
    )
    with pytest.raises(ValueError, match="boolean"):
        config.validate()
