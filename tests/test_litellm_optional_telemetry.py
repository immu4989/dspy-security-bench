"""Broken optional metadata must not interrupt the reference agent's real tools."""

import asyncio
import json
import sys
from types import SimpleNamespace

import pytest

from dspy_security_bench.agents import BenchTool, LiteLLMFunctionCallingAgent
from dspy_security_bench.agents.litellm_fc import _response_usage


def response(*, tools=False, fault=None, error=ValueError):
    def fail():
        raise error("PRIVATE synthetic telemetry")

    class Usage:
        def __getattr__(self, name):
            if name == fault:
                fail()
            return {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}.get(name)

    class Cost(dict):
        def get(self, key, *args):
            if fault == "response_cost":
                fail()
            return super().get(key, *args)

    call = SimpleNamespace(id="call-1", type="function", function=SimpleNamespace(name="record", arguments='{"record_id":"R-1"}'))
    call.model_dump = lambda: {"id": call.id, "type": "function", "function": {
        "name": "record", "arguments": call.function.arguments,
    }}
    message = SimpleNamespace(role="assistant", content=None if tools else "done", tool_calls=[call] if tools else [])

    class Response:
        choices = [SimpleNamespace(message=message, finish_reason="tool_calls" if tools else "stop")]

        @property
        def usage(self):
            if fault == "usage":
                fail()
            return Usage()

        @property
        def _hidden_params(self):
            if fault == "_hidden_params":
                fail()
            return Cost(response_cost=0.25)

    return Response()


def backend(monkeypatch, responses):
    calls = []
    iterator = iter(responses)

    def completion(**kwargs):
        calls.append(kwargs)
        value = next(iterator)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    return calls


@pytest.mark.parametrize("fault", ["usage", "prompt_tokens", "completion_tokens", "total_tokens", "_hidden_params", "response_cost"])
@pytest.mark.parametrize("fault_at", [0, 1, 2])
@pytest.mark.parametrize("forced_final", [False, True])
def test_bad_telemetry_never_changes_tool_execution_or_publishes_partial_totals(monkeypatch, fault, fault_at, forced_final):
    calls = backend(monkeypatch, [response(tools=index < 2, fault=fault if index == fault_at else None) for index in range(3)])
    effects = []
    tool = BenchTool("record", "Record synthetic action", {}, lambda **kwargs: effects.append(kwargs) or "recorded")
    result = LiteLLMFunctionCallingAgent("fixture", max_iters=2 if forced_final else 3).run("query", [tool])
    assert result.final_answer == "done"
    assert effects == [{"record_id": "R-1"}] * 2
    assert len(result.tool_calls) == 2 and all(call.result == "recorded" for call in result.tool_calls)
    expected = {"prompt_tokens": 6, "completion_tokens": 9, "total_tokens": 15, "estimated_cost_usd": 0.75}
    if fault == "usage":
        expected = {"estimated_cost_usd": 0.75}
    else:
        expected.pop("estimated_cost_usd" if fault in {"_hidden_params", "response_cost"} else fault)
    assert result.usage == expected
    assert "PRIVATE" not in json.dumps(result.usage, allow_nan=False)
    assert len(calls) == 3 and ("tools" not in calls[-1]) is forced_final


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
@pytest.mark.parametrize("fault", ["usage", "prompt_tokens", "_hidden_params", "response_cost"])
def test_control_flow_during_optional_access_still_propagates(error, fault):
    with pytest.raises(error):
        _response_usage(response(fault=fault, error=error))


def test_unexpected_telemetry_types_are_not_coerced_or_called():
    class Private:
        def __str__(self):
            pytest.fail("telemetry must not be stringified")

        def __float__(self):
            pytest.fail("telemetry must not be coerced")

        def __call__(self):
            pytest.fail("LiteLLM telemetry fields are data, not methods")

    assert _response_usage(SimpleNamespace(usage=Private(), _hidden_params={"response_cost": Private()})) == {}


def test_mapping_field_failure_preserves_neighboring_tokens():
    class Usage(dict):
        def get(self, key, *args):
            if key == "prompt_tokens":
                raise ValueError("PRIVATE mapping failure")
            return super().get(key, *args)

    assert _response_usage(SimpleNamespace(usage=Usage(prompt_tokens=2, completion_tokens=3, total_tokens=5))) == {
        "completion_tokens": 3, "total_tokens": 5,
    }


@pytest.mark.parametrize("source", ["provider", "tool", "required-response"])
def test_ordinary_execution_failures_are_not_treated_as_optional_telemetry(monkeypatch, source):
    failure = LookupError("PRIVATE required execution failure")

    class InvalidResponse:
        @property
        def choices(self):
            raise failure

    calls = backend(monkeypatch, [response(tools=True, fault="usage"),
                                  failure if source == "provider" else InvalidResponse()])
    effects = []

    def record():
        effects.append(True)
        if source == "tool":
            raise failure
        return "recorded"

    with pytest.raises(LookupError) as captured:
        LiteLLMFunctionCallingAgent("fixture").run("query", [BenchTool("record", "Synthetic action", {}, lambda **kwargs: record())])
    assert captured.value is failure and effects == [True]
    assert len(calls) == (1 if source == "tool" else 2)


def test_native_litellm_response_objects_retain_reported_values_without_provider_calls(monkeypatch):
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    attempts = []

    def no_network(*args, **kwargs):
        attempts.append(True)
        pytest.fail("native response fixture must not contact providers or pricing services")

    monkeypatch.setattr("socket.socket.connect", no_network)
    monkeypatch.setattr("socket.socket.connect_ex", no_network)
    monkeypatch.setattr("socket.getaddrinfo", no_network)
    from litellm.types.utils import ModelResponse

    native = ModelResponse(choices=[{"message": {"role": "assistant", "content": "done"}, "finish_reason": "stop", "index": 0}],
                           usage={"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5})
    native._hidden_params["response_cost"] = 0.25
    backend(monkeypatch, [native])
    result = LiteLLMFunctionCallingAgent("fixture").run("query", [])
    assert result.final_answer == "done" and result.tool_calls == []
    assert result.usage == {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5, "estimated_cost_usd": 0.25}
    assert not attempts
