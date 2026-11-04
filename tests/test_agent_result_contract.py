"""Result admission is independent of optional telemetry and never stringifies data."""

import asyncio

import pytest

from dspy_security_bench.agents import (
    AgentResult,
    AgentResultError,
    ToolCall,
    validate_agent_result,
)
from dspy_security_bench.integrations.frameworks import CallbackAdapter


class Unprintable:
    def __str__(self):
        pytest.fail("must not stringify private result data")

    def __repr__(self):
        pytest.fail("must not represent private result data")


@pytest.mark.parametrize("value", [None, False, 0, "PRIVATE", {}, Unprintable()],
                         ids=["none", "bool", "number", "text", "mapping", "unprintable"])
def test_required_result_object_is_not_coerced(value):
    with pytest.raises(AgentResultError, match="must return an AgentResult") as caught:
        validate_agent_result(value)
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize("value", [None, False, 0, {"PRIVATE": 1}, Unprintable()],
                         ids=["none", "bool", "number", "mapping", "unprintable"])
def test_final_answer_must_be_explicit_text(value):
    with pytest.raises(AgentResultError, match="final_answer must be text"):
        validate_agent_result(AgentResult(value))


@pytest.mark.parametrize("trace", [None, (), {}, [None], [Unprintable()]],
                         ids=["none", "tuple", "mapping", "none-entry", "unprintable-entry"])
def test_supplied_trace_requires_a_list_of_tool_calls(trace):
    with pytest.raises(AgentResultError, match="tool_calls"):
        validate_agent_result(AgentResult("", tool_calls=trace))


@pytest.mark.parametrize("field,value", [
    ("name", None), ("name", " \n"), ("name", Unprintable()),
    ("args", None), ("args", []), ("args", Unprintable()),
    ("result", None), ("result", 0), ("result", Unprintable()),
], ids=["missing-name", "blank-name", "object-name", "missing-args", "array-args",
        "object-args", "missing-result", "numeric-result", "object-result"])
def test_tool_call_fields_are_not_substituted_or_stringified(field, value):
    call = ToolCall("lookup", {}, "")
    setattr(call, field, value)
    with pytest.raises(AgentResultError, match="ToolCall." + field):
        validate_agent_result(AgentResult("", tool_calls=[call]))


@pytest.mark.parametrize("usage", [None, [], {"total_tokens": False}, {"estimated_cost_usd": float("nan")}])
def test_empty_refusal_and_optional_invalid_telemetry_are_not_execution_errors(usage):
    result = AgentResult("", tool_calls=[ToolCall("lookup", {}, "")], usage=usage)
    assert validate_agent_result(result) is result
    assert result.usage is usage


def test_shape_check_does_not_claim_recursive_json_validation_or_trace_authenticity():
    result = AgentResult("answer", tool_calls=[ToolCall("self-reported", {"opaque": Unprintable()}, "")])
    assert validate_agent_result(result) is result


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("value", [None, {}, Unprintable(), AgentResult(None)],
                         ids=["none", "mapping", "unprintable", "bad-agent-result"])
def test_callback_contract_rejects_invalid_sync_and_async_results(asynchronous, value):
    async def async_runner(*args):
        return value

    runner = async_runner if asynchronous else lambda *args: value
    with pytest.raises(AgentResultError):
        CallbackAdapter(runner).run("query", [])


@pytest.mark.parametrize("value", ["", "answer", AgentResult("answer")])
def test_callback_preserves_supported_outputs_inside_a_running_event_loop(value):
    async def runner(*args):
        return value

    async def invoke():
        return CallbackAdapter(runner).run("query", [])

    result = asyncio.run(invoke())
    if isinstance(value, AgentResult):
        assert result is value
    else:
        assert result.final_answer == value
