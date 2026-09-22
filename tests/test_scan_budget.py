"""Execution budgets count benchmark work, not guessed provider prices."""

import json

import pytest

from dspy_security_bench.scan.cli import build_execution_budget, build_scan_plan, main
from dspy_security_bench.scan.config import ScanConfig


def config(limit):
    return ScanConfig.from_dict({"agent": {"model": "fixture"}, "limits": {"max_task_runs": limit},
        "scan": {"attacks": ["direct", "dos"], "defenses": ["none", "security_prompt"], "user_tasks": 2, "injection_tasks": 3}})


def test_budget_includes_auxiliary_runs_and_dos_convention():
    cfg = config(22)
    budget = build_execution_budget(cfg, build_scan_plan(cfg))
    assert budget["planned_task_runs"] == 22  # 16 scored plus 6 auxiliary.
    assert budget["within_budget"]
    cfg.limits.max_task_runs = 21
    assert not build_execution_budget(cfg, build_scan_plan(cfg))["within_budget"]


@pytest.mark.parametrize("limit", [True, 0, -1, 1.5, "10", 1000001])
def test_invalid_budgets_are_rejected(limit):
    with pytest.raises(ValueError, match="max_task_runs"):
        config(limit).validate()


def test_over_budget_scope_is_reviewable_but_never_constructs_agent(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("over-budget scan must not construct an agent")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    args = ["--agent-model", "fixture", "--attacks", "direct", "--user-tasks", "2",
            "--injection-tasks", "1", "--max-task-runs", "2"]
    output = tmp_path / "plan.json"
    assert main([*args, "--plan-json", str(output)]) == 0
    budget = json.loads(output.read_text())["execution_budget"]
    assert budget["planned_task_runs"] == 3 and not budget["within_budget"]
    assert "within_budget=False" in capsys.readouterr().out
    assert main([*args, "--fail-on", "never"]) == 2
    baseline = tmp_path / "baseline.json"
    assert main([*args, "--write-baseline", str(baseline)]) == 2
    assert not baseline.exists()


def test_budget_changes_are_bound_by_plan_pin(tmp_path, monkeypatch):
    output = tmp_path / "plan.json"
    args = ["--agent-model", "fixture", "--max-task-runs", "100"]
    assert main([*args, "--plan-json", str(output)]) == 0
    digest = json.loads(output.read_text())["report_sha256"]

    def forbidden(*args, **kwargs):
        pytest.fail("changed reviewed budget must not construct an agent")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    assert main(["--agent-model", "fixture", "--max-task-runs", "101", "--expected-plan-sha256", digest]) == 2


def test_inclusive_budget_allows_agent_construction(monkeypatch):
    calls = []

    def stop(*args):
        calls.append(True)
        raise RuntimeError("test ends before model calls")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", stop)
    assert main(["--agent-model", "fixture", "--attacks", "direct", "--user-tasks", "2",
                 "--injection-tasks", "1", "--max-task-runs", "3"]) == 2
    assert calls == [True]
