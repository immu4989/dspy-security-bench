"""Reference-agent execution failures and malformed calls must remain distinct."""

import sys
from types import SimpleNamespace

import pytest

from dspy_security_bench.adapters.execution import BenchmarkExecutionError, ExecutionCheckedSuite
from dspy_security_bench.agents.base import BenchTool
from dspy_security_bench.agents.litellm_fc import LiteLLMFunctionCallingAgent, _response_usage


def response(arguments=None, *, final=False):
    call = SimpleNamespace(id="call-1", function=SimpleNamespace(name="act", arguments=arguments))
    call.model_dump = lambda: {"id": call.id, "type": "function", "function": {"name": "act", "arguments": arguments}}
    message = SimpleNamespace(content="done" if final else None, tool_calls=[] if final else [call])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage={"total_tokens": 2})


def backend(monkeypatch, answers):
    calls = []
    iterator = iter(answers)

    def completion(**kwargs):
        calls.append(kwargs)
        value = next(iterator)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion, drop_params=False))
    return calls


@pytest.mark.parametrize("arguments", ["{", "[]", "true", "null", '{"x":1,"x":2}', '{"x":NaN}', "", None, 0, "x" * 1_000_001],
                         ids=["malformed", "array", "boolean", "null", "duplicate", "nonfinite", "empty", "none", "integer", "oversized"])
def test_malformed_arguments_never_execute_default_tool_actions(monkeypatch, arguments):
    executions = []
    calls = backend(monkeypatch, [response(arguments), response(final=True)])
    tool = BenchTool("act", "fixture", {}, lambda **kwargs: executions.append(kwargs) or "executed")
    result = LiteLLMFunctionCallingAgent("fixture", max_iters=2).run("fictional query", [tool])
    assert executions == []
    assert result.final_answer == "done"
    assert "tool was not executed" in result.tool_calls[0].result
    assert result.tool_calls[0].args == {}
    assert len(calls) == 2


@pytest.mark.parametrize("arguments", ['{"x":1}', {"x": 1}, "{}"])
def test_valid_object_arguments_execute_the_supplied_callable(monkeypatch, arguments):
    executions = []
    backend(monkeypatch, [response(arguments), response(final=True)])
    tool = BenchTool("act", "fixture", {}, lambda **kwargs: executions.append(kwargs) or "executed")
    result = LiteLLMFunctionCallingAgent("fixture", max_iters=2).run("query", [tool])
    assert len(executions) == 1
    assert result.tool_calls[0].result == "executed"
    assert result.usage["total_tokens"] == 4


def test_final_answer_provider_failure_propagates_without_logging_payload(monkeypatch, caplog):
    calls = backend(monkeypatch, [response("{}"), RuntimeError("fictional-private-provider-payload")])
    tool = BenchTool("act", "fixture", {}, lambda: "executed")
    agent = LiteLLMFunctionCallingAgent("fixture", max_iters=1)

    class Suite:
        def run_task_with_pipeline(self):
            agent.run("query", [tool])
            return False, False

    with pytest.raises(BenchmarkExecutionError) as caught:
        ExecutionCheckedSuite(Suite()).run_task_with_pipeline()
    assert "fictional-private-provider-payload" not in str(caught.value) + caplog.text
    assert len(calls) == 2 and "tools" not in calls[-1]


def test_duplicate_tool_names_are_rejected_before_provider_access(monkeypatch):
    calls = backend(monkeypatch, [])
    tool = BenchTool("act", "fixture", {}, lambda: "executed")
    with pytest.raises(ValueError, match="unique"):
        LiteLLMFunctionCallingAgent("fixture").run("query", [tool, tool])
    assert calls == []


@pytest.mark.parametrize("setting,value", [("max_iters", 0), ("max_iters", True), ("max_iters", 1001), ("max_tokens", 0), ("num_retries", -1), ("num_retries", 101)])
def test_reference_agent_rejects_invalid_execution_limits(setting, value):
    with pytest.raises(ValueError):
        LiteLLMFunctionCallingAgent("fixture", **{setting: value})


@pytest.mark.parametrize("cost", [float("nan"), float("inf"), -1, True, 10**400])
def test_invalid_cost_metadata_is_not_reported_as_an_estimate(cost):
    assert "estimated_cost_usd" not in _response_usage(SimpleNamespace(_hidden_params={"response_cost": cost}))
