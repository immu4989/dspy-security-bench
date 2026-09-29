"""Cooperative tool admission stays bounded across errors, threads, and task reuse."""

import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from importlib.resources import files
from threading import Event, Thread

import jsonschema
import pytest

from dspy_security_bench.adapters.execution import BenchmarkExecutionError, ExecutionCheckedSuite
from dspy_security_bench.agents import AgentResult, AgentToolBudgetError, BenchTool, ToolBudgetAgent
from dspy_security_bench.agents.budget import TOOL_BUDGET_PROTOCOL
from dspy_security_bench.scan.cli import build_scan_plan, build_scan_scope, main
from dspy_security_bench.scan.compare import compare_scan_evidence
from dspy_security_bench.scan.config import ScanConfig
from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.evidence import (
    build_scan_evidence,
    expected_observation_keys,
    verify_scan_evidence,
)
from dspy_security_bench.scan.study import build_scan_study, build_study_plan


class FixtureAgent:
    name = "fixture-agent"

    def __init__(self, run):
        self.callback = run

    def run(self, query, tools, *, system_directive=""):
        return self.callback(query, tools, system_directive)


def test_cap_is_inclusive_and_resets_per_run_without_changing_inputs():
    effects = []
    tool = BenchTool("act", "fixture", {"type": "object"}, lambda **kw: effects.append(kw) or "done")

    def execute(query, tools, directive):
        assert query == "q" and directive == "policy"
        assert tools[0] is not tool
        tools[0].parameters["extra"] = "local-only"
        tools[0](n=1)
        tools[0](n=2)
        return AgentResult("done")

    agent = ToolBudgetAgent(FixtureAgent(execute), 2)
    assert agent.name == "fixture-agent"
    assert agent.run("q", [tool], system_directive="policy").final_answer == "done"
    assert agent.run("q", [tool], system_directive="policy").final_answer == "done"
    assert effects == [{"n": 1}, {"n": 2}, {"n": 1}, {"n": 2}]
    assert tool.parameters == {"type": "object"}


def test_swallowed_budget_error_cannot_become_a_complete_safe_result():
    effects = []
    tool = BenchTool("act", "fixture", {}, lambda: effects.append(True) or "done")

    def execute(query, tools, directive):
        tools[0]()
        try:
            tools[0]()
        except AgentToolBudgetError:
            pass
        return AgentResult("pretend complete")

    agent = ToolBudgetAgent(FixtureAgent(execute), 1)
    with pytest.raises(AgentToolBudgetError, match="no complete measurement"):
        agent.run("q", [tool])
    assert effects == [True]


def test_failed_tool_callback_consumes_admission():
    effects = []

    def action():
        effects.append(True)
        raise ValueError("fictional tool failure")

    def execute(query, tools, directive):
        with pytest.raises(ValueError):
            tools[0]()
        tools[0]()

    with pytest.raises(AgentToolBudgetError):
        ToolBudgetAgent(FixtureAgent(execute), 1).run("q", [BenchTool("act", "", {}, action)])
    assert effects == [True]


def test_parallel_invocations_cannot_overspend_shared_task_budget():
    effects = []
    tool = BenchTool("act", "", {}, lambda: effects.append(True) or "done")

    def execute(query, tools, directive):
        def attempt(_):
            try:
                return tools[0]()
            except AgentToolBudgetError:
                return "denied"

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(40)))
        assert outcomes.count("done") == 3
        return AgentResult("done")

    with pytest.raises(AgentToolBudgetError):
        ToolBudgetAgent(FixtureAgent(execute), 3).run("q", [tool])
    assert len(effects) == 3


@pytest.mark.parametrize("fail", [False, True])
def test_captured_tools_close_after_agent_returns_or_raises(fail):
    captured, effects = [], []

    def execute(query, tools, directive):
        captured.extend(tools)
        if fail:
            raise ValueError("fixture")
        return AgentResult("done")

    agent = ToolBudgetAgent(FixtureAgent(execute), 2)
    tool = BenchTool("act", "", {}, lambda: effects.append(True) or "done")
    if fail:
        with pytest.raises(ValueError):
            agent.run("q", [tool])
    else:
        agent.run("q", [tool])
    with pytest.raises(AgentToolBudgetError, match="closed"):
        captured[0]()
    assert effects == []


def test_agent_returning_with_admitted_callback_in_flight_is_incomplete():
    started, release = Event(), Event()
    workers = []

    def action():
        started.set()
        assert release.wait(5)
        return "done"

    def execute(query, tools, directive):
        thread = Thread(target=tools[0])
        workers.append(thread)
        thread.start()
        assert started.wait(2)
        return AgentResult("too early")

    try:
        with pytest.raises(AgentToolBudgetError, match="still running"):
            ToolBudgetAgent(FixtureAgent(execute), 1).run("q", [BenchTool("act", "", {}, action)])
    finally:
        release.set()
        for worker in workers:
            worker.join(2)
            assert not worker.is_alive()


@pytest.mark.parametrize("limit", [True, 0, -1, 1.5, "2", None, 10001])
def test_invalid_admission_limits_fail_before_agent_access(limit):
    with pytest.raises(ValueError):
        ToolBudgetAgent(None, limit)


def test_budget_exhaustion_remains_execution_error_at_suite_boundary():
    def execute(query, tools, directive):
        tools[0]()
        tools[0]()

    agent = ToolBudgetAgent(FixtureAgent(execute), 1)

    class Suite:
        def run_task_with_pipeline(self):
            agent.run("q", [BenchTool("act", "", {}, lambda: "done")])
            return True, False

    with pytest.raises(BenchmarkExecutionError):
        ExecutionCheckedSuite(Suite()).run_task_with_pipeline()


def test_budgeted_scope_is_distinct_replayable_and_bound_to_plan_pin(tmp_path, monkeypatch):
    base = ["--agent-model", "fixture", "--max-tool-calls-per-task", "2"]
    output = tmp_path / "plan.json"
    assert main([*base, "--plan-json", str(output)]) == 0
    plan = json.loads(output.read_text())
    assert plan["scope"]["measurement_protocol"] == TOOL_BUDGET_PROTOCOL
    assert plan["scope"]["execution_controls"] == {"max_tool_calls_per_task": 2}

    def forbidden(*args):
        pytest.fail("changed tool budget must reject before agent construction")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    assert main(["--agent-model", "fixture", "--max-tool-calls-per-task", "3",
                 "--expected-plan-sha256", plan["report_sha256"]]) == 2


def test_legacy_and_budgeted_evidence_remain_explicitly_incomparable():
    legacy = json.loads(build_demo_artifacts()["before.json"])
    scope = deepcopy(legacy["scope"])
    scope.update(measurement_protocol=TOOL_BUDGET_PROTOCOL, execution_controls={"max_tool_calls_per_task": 2})
    bounded = build_scan_evidence(scope, legacy["policy"], legacy["observations"])
    verify_scan_evidence(bounded)
    schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-evidence.schema.json").read_text())
    jsonschema.validate(bounded, schema)
    jsonschema.validate(legacy, schema)
    with pytest.raises(ValueError, match="matched scopes"):
        compare_scan_evidence(legacy, bounded)
    plan = build_study_plan(bounded, "budgeted-study", 2)
    trials = [{"trial_id": name, "status": "complete", "evidence_sha256": bounded["evidence_sha256"]}
              for name in plan["trial_ids"]]
    report = build_scan_study(plan, trials, dict.fromkeys(plan["trial_ids"], bounded))
    study_schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-study.schema.json").read_text())
    jsonschema.validate(report, study_schema)
    assert study_schema["$defs"]["scope"] == schema["$defs"]["scope"]


@pytest.mark.parametrize("protocol,controls", [
    (TOOL_BUDGET_PROTOCOL, None), (TOOL_BUDGET_PROTOCOL, {}),
    (TOOL_BUDGET_PROTOCOL, {"max_tool_calls_per_task": True}),
    (TOOL_BUDGET_PROTOCOL, {"max_tool_calls_per_task": 10001}),
    ("complete-binary-observations-v2", {"max_tool_calls_per_task": 2}),
])
def test_scope_cannot_silently_drop_or_relabel_budget(protocol, controls):
    scope = json.loads(build_demo_artifacts()["before.json"])["scope"]
    scope["measurement_protocol"] = protocol
    if controls is not None:
        scope["execution_controls"] = controls
    with pytest.raises(ValueError):
        expected_observation_keys(scope)


def test_default_scope_contract_does_not_change():
    cfg = ScanConfig.from_dict({"agent": {"model": "fixture"}})
    scope = build_scan_scope(cfg, build_scan_plan(cfg))
    assert scope["measurement_protocol"] == "complete-binary-observations-v2"
    assert "execution_controls" not in scope


def test_scan_wraps_agent_and_writes_no_report_for_exhausted_task(tmp_path, monkeypatch):
    def execute(query, tools, directive):
        tools[0]()
        tools[0]()

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda spec: FixtureAgent(execute))

    def evaluate(agents, **kwargs):
        agent = next(iter(agents.values()))
        assert isinstance(agent, ToolBudgetAgent)
        agent.run("q", [BenchTool("act", "", {}, lambda: "done")])
        pytest.fail("exhausted task must not return benchmark outcomes")

    monkeypatch.setattr("dspy_security_bench.runner.evaluate_agents", evaluate)
    output = tmp_path / "evidence.json"
    assert main(["--agent-model", "fixture", "--max-tool-calls-per-task", "1",
                 "--fail-on", "never", "--evidence-json", str(output)]) == 2
    assert not output.exists()


def test_active_run_uses_a_snapshot_of_its_admission_limit():
    effects = []
    wrapper = None

    def action():
        effects.append(True)
        wrapper.max_tool_calls_per_task = 100
        return "done"

    def execute(query, tools, directive):
        tools[0]()
        tools[0]()

    wrapper = ToolBudgetAgent(FixtureAgent(execute), 1)
    with pytest.raises(AgentToolBudgetError):
        wrapper.run("q", [BenchTool("act", "", {}, action)])
    assert effects == [True]
