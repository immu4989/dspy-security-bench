import json

import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.cli import main


def no_agent(*args, **kwargs):
    pytest.fail("preflight must not construct an agent")


def test_json_plan_is_deterministic_and_never_calls_model(tmp_path, monkeypatch):
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", no_agent)
    first, second = tmp_path / "one.json", tmp_path / "two.json"
    args = [
        "--agent-model",
        "fixture",
        "--attacks",
        "direct",
        "dos",
        "--user-tasks",
        "2",
        "--injection-tasks",
        "3",
    ]
    assert main([*args, "--plan-json", str(first)]) == 0
    assert main([*args, "--plan-json", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()
    report = json.loads(first.read_text())
    digest = report.pop("report_sha256")
    assert canonical_sha256(report) == digest
    assert report["scope_sha256"] == canonical_sha256(report["scope"])
    assert report["summary"] == {
        "scored_cases": 8,
        "auxiliary_injection_task_runs": 3,
        "model_calls_performed": 0,
        "execution_performed": False,
    }
    assert main([*args, "--plan-json", str(first)]) == 2


@pytest.mark.parametrize(
    "collision",
    ["same-output", "config", "baseline", "hardlink", "symlink", "directory", "missing-parent"],
)
def test_bad_output_targets_stop_before_model_calls(tmp_path, monkeypatch, collision):
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", no_agent)
    monkeypatch.setattr("dspy_security_bench.scan.cli.build_scan_plan", no_agent)
    config = tmp_path / "config.yaml"
    config.write_text("agent: {model: fixture}\n")
    json_out = tmp_path / "scan.json"
    sarif_out = tmp_path / "scan.sarif"
    args = ["--config", str(config)]
    if collision == "same-output":
        sarif_out = json_out
    elif collision == "config":
        json_out = config
    elif collision == "baseline":
        json_out.write_text('{"security_by_cell":{}}')
        args += ["--baseline", str(json_out)]
    elif collision == "hardlink":
        json_out.write_text("retained")
        sarif_out.hardlink_to(json_out)
    elif collision == "symlink":
        json_out.symlink_to(config)
    elif collision == "directory":
        json_out.mkdir()
    else:
        json_out = tmp_path / "missing" / "scan.json"
    original = config.read_bytes()
    assert main([*args, "--json", str(json_out), "--sarif", str(sarif_out)]) == 2
    assert config.read_bytes() == original


def test_plan_json_cannot_replace_input_yaml(tmp_path, monkeypatch):
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", no_agent)
    config = tmp_path / "config.yaml"
    config.write_text("agent: {model: fixture}\n")
    original = config.read_bytes()
    assert main(["--config", str(config), "--plan-json", str(config)]) == 2
    assert config.read_bytes() == original
