"""Exercise real AgentDojo fallback paths without provider requests or trace files."""

from types import SimpleNamespace

import httpx
import pytest
from openai import BadRequestError

from dspy_security_bench.adapters.execution import BenchmarkExecutionError, ExecutionCheckedSuite
from dspy_security_bench.runner import _run_attack_matrix, evaluate_agents, evaluate_factories


class NoDiskTrace:
    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def set_contextarg(self, *args):
        pass

    def log_error(self, *args):
        pytest.fail("provider exception reached AgentDojo's binary fallback")


class FakeSuite:
    name = "fixture"
    user_tasks = {"u": SimpleNamespace(ID="u")}
    injection_tasks = {"i": SimpleNamespace(ID="i")}

    def __init__(self, phase="none", error=None):
        self.phase, self.error = phase, error
        self.calls = 0

    def get_user_task_by_id(self, value):
        return self.user_tasks[value]

    def get_injection_task_by_id(self, value):
        return self.injection_tasks[value]

    def run_task_with_pipeline(self, pipeline, task, injection_task=None, injections=None):
        self.calls += 1
        phase = "scored" if injection_task is not None else "auxiliary"
        if phase == self.phase:
            raise self.error
        return True, injection_task is None


def run(monkeypatch, suite):
    monkeypatch.setattr("agentdojo.benchmark.TraceLogger", NoDiskTrace)
    attack = SimpleNamespace(is_dos_attack=False, name="direct", attack=lambda *args: {})
    monkeypatch.setattr("dspy_security_bench.runner.load_attack", lambda *args: attack)
    return _run_attack_matrix(SimpleNamespace(name="fixture"), suite, ["direct"], "agent", "fixture", "none", ["u"], ["i"], None, True, False)


def provider_error():
    return BadRequestError(
        "PRIVATE provider account and prompt details",
        response=httpx.Response(400, request=httpx.Request("POST", "https://example.invalid")),
        body={"code": "context_length_exceeded", "param": "max_tokens"},
    )


@pytest.mark.parametrize("phase", ["auxiliary", "scored"])
@pytest.mark.parametrize("error", [provider_error(), RuntimeError("PRIVATE evaluator details")])
def test_exceptions_never_become_binary_attack_outcomes(monkeypatch, phase, error):
    suite = FakeSuite(phase, error)
    with pytest.raises(BenchmarkExecutionError, match="no binary outcome") as captured:
        run(monkeypatch, suite)
    assert "PRIVATE" not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__
    assert suite.calls == (1 if phase == "auxiliary" else 2)


def test_successful_task_measurements_still_use_upstream_benchmark(monkeypatch):
    suite = FakeSuite()
    rows = run(monkeypatch, suite)
    assert suite.calls == 2  # auxiliary utility plus scored pair
    assert rows[0]["security"] == 1 and rows[0]["utility"] == 1


def test_real_workspace_suite_accepts_guarded_no_model_agent(monkeypatch):
    from dspy_security_bench.agents import AgentResult

    monkeypatch.setattr("agentdojo.benchmark.TraceLogger", NoDiskTrace)
    monkeypatch.setattr("socket.socket.connect", lambda *args: pytest.fail("offline fixture must not connect"))
    agent = SimpleNamespace(name="offline-refusal", run=lambda *args, **kwargs: AgentResult(final_answer="Declined", tool_calls=[]))
    with pytest.warns(UserWarning, match="Not all injection tasks"):
        frame = evaluate_agents({"offline-refusal": agent}, suite_name="workspace",
                                attacks=["direct"], user_task_ids=["user_task_0"],
                                injection_task_ids=["injection_task_0"])
    assert len(frame) == 1
    assert frame.iloc[0]["utility"] == 0
    assert frame.iloc[0]["security"] == 1


def test_execution_error_cli_returns_two_without_publishing_a_gate(monkeypatch, tmp_path, capsys):
    from dspy_security_bench.scan.cli import main

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda cfg: object())
    def fail(**kwargs):
        raise BenchmarkExecutionError("task execution or evaluation failed; no binary outcome was recorded")
    monkeypatch.setattr("dspy_security_bench.runner.evaluate_agents", fail)
    output, evidence = tmp_path / "report.json", tmp_path / "evidence.json"
    assert main(["--agent-model", "fixture", "--json", str(output), "--evidence-json", str(evidence)]) == 2
    assert not output.exists() and not evidence.exists()
    assert "BenchmarkExecutionError" in capsys.readouterr().err


@pytest.mark.parametrize("outcome", [None, (True,), (True, 0), (1, False), [True, False], (True, False, True)])
def test_nonboolean_or_malformed_task_measurements_are_execution_errors(outcome):
    suite = SimpleNamespace(run_task_with_pipeline=lambda *args: outcome)
    with pytest.raises(BenchmarkExecutionError, match="two measured boolean"):
        ExecutionCheckedSuite(suite).run_task_with_pipeline()


def test_keyboard_interrupt_is_not_converted_to_an_execution_result():
    def interrupt():
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        ExecutionCheckedSuite(SimpleNamespace(run_task_with_pipeline=interrupt)).run_task_with_pipeline()


@pytest.mark.parametrize("api,argument", [(evaluate_agents, {"agents": {"a": object()}}),
                                         (evaluate_factories, {"factories": {"a": lambda: object()}})])
def test_legacy_cached_outcomes_are_rejected_before_suite_or_agent_work(monkeypatch, api, argument):
    monkeypatch.setattr("dspy_security_bench.runner.get_suite", lambda *args: pytest.fail("no suite loading"))
    with pytest.raises(ValueError, match="cached AgentDojo outcomes"):
        api(**argument, force_rerun=False)
