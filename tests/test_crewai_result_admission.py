"""CrewAI answer attribution and awaitable handling without optional SDKs."""

import asyncio
import sys
from contextvars import ContextVar
from types import ModuleType, SimpleNamespace

import pytest

from dspy_security_bench.agents import AgentResultError, BenchTool
from dspy_security_bench.integrations import CrewAIAdapter


class PrivateValue:
    def __str__(self):
        pytest.fail("non-text native output must not be stringified")

    def __repr__(self):
        pytest.fail("non-text native output must not be represented")


def run(monkeypatch, native_result, effects, *, asynchronous=False, inside_loop=False, failure=None):
    request = ContextVar("crewai-fixture-request", default="missing")

    class Agent:
        def __init__(self, **kwargs):
            assert kwargs["llm"] == "fixture" and kwargs["goal"].startswith("trusted")
            assert kwargs["role"] == "fixture-role" and not kwargs["allow_delegation"]
            self.tools = kwargs["tools"]

        def kickoff(self, query):
            def execute():
                assert request.get() == "request-1" and query == "PRIVATE query"
                self.tools[0]()
                if failure:
                    raise failure
                return native_result

            async def execute_async():
                await asyncio.sleep(0)
                return execute()

            return execute_async() if asynchronous else execute()

    module, tool_module = ModuleType("crewai"), ModuleType("crewai.tools")
    module.Agent = Agent
    tool_module.tool = lambda name: lambda function: function
    monkeypatch.setitem(sys.modules, "crewai", module)
    monkeypatch.setitem(sys.modules, "crewai.tools", tool_module)
    agent = CrewAIAdapter(model="fixture", name="fixture-role")
    tools = [BenchTool("record", "Synthetic action", {}, lambda: effects.append(True) or "recorded")]

    def invoke():
        token = request.set("request-1")
        try:
            return agent.run("PRIVATE query", tools, system_directive="trusted")
        finally:
            request.reset(token)

    async def invoke_inside_loop():
        return invoke()

    result = asyncio.run(invoke_inside_loop()) if inside_loop else invoke()
    assert request.get() == "missing"
    return result


@pytest.mark.parametrize("raw", [None, False, 0, {}, ["answer"], {"text": "PRIVATE"}, PrivateValue()],
                         ids=["none", "bool", "number", "mapping", "array", "text-mapping", "private"])
def test_non_text_raw_is_not_an_answer(monkeypatch, raw):
    effects = []
    with pytest.raises(AgentResultError, match="final_answer must be text") as captured:
        run(monkeypatch, SimpleNamespace(raw=raw, agent_role="fixture-role"), effects)
    assert "PRIVATE" not in str(captured.value)
    assert effects == [True]


@pytest.mark.parametrize("role", [None, False, 0, [], PrivateValue(), "PRIVATE other agent"],
                         ids=["none", "bool", "number", "array", "private", "different"])
def test_answer_role_must_match_selected_agent(monkeypatch, role):
    with pytest.raises(AgentResultError, match="role must match") as captured:
        run(monkeypatch, SimpleNamespace(raw="PRIVATE answer", agent_role=role), [])
    assert "PRIVATE" not in str(captured.value)


@pytest.mark.parametrize("result", [None, SimpleNamespace(), SimpleNamespace(raw="answer"),
                                     {"raw": "answer", "agent_role": "fixture-role"}, "answer"],
                         ids=["none", "missing-fields", "missing-role", "serialized", "bare-text"])
def test_missing_native_envelope_is_not_an_empty_answer(monkeypatch, result):
    with pytest.raises(AgentResultError):
        run(monkeypatch, result, [])


def test_missing_raw_does_not_default_to_empty_text(monkeypatch):
    with pytest.raises(AgentResultError, match="final_answer must be text"):
        run(monkeypatch, SimpleNamespace(agent_role="fixture-role"), [])


@pytest.mark.parametrize("answer", ["", "answer", '{"answer":"already serialized by SDK"}'])
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("inside_loop", [False, True])
def test_text_preserves_context_trace_and_usage(monkeypatch, answer, asynchronous, inside_loop):
    native = SimpleNamespace(raw=answer, agent_role="fixture-role", pydantic=PrivateValue(),
                             usage_metrics={"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5})
    effects = []
    result = run(monkeypatch, native, effects, asynchronous=asynchronous, inside_loop=inside_loop)
    assert result.final_answer == answer and effects == [True]
    assert result.usage == {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
    assert len(result.tool_calls) == 1 and result.tool_calls[0].result == "recorded"


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("inside_loop", [False, True])
@pytest.mark.parametrize("failure", [LookupError("synthetic failure"), asyncio.CancelledError()],
                         ids=["error", "cancelled"])
def test_failed_kickoff_preserves_exception_and_prior_effects(monkeypatch, asynchronous, inside_loop, failure):
    effects = []
    with pytest.raises(type(failure)) as captured:
        run(monkeypatch, None, effects, asynchronous=asynchronous, inside_loop=inside_loop, failure=failure)
    # Python 3.10 Task cancellation may produce a new CancelledError instance.
    if not isinstance(failure, asyncio.CancelledError):
        assert captured.value is failure
    assert effects == [True]


def test_invalid_output_precedes_optional_usage_access(monkeypatch):
    class InvalidResult:
        agent_role = "fixture-role"
        raw = None

        @property
        def usage_metrics(self):
            pytest.fail("usage must not be accessed before required result admission")

    with pytest.raises(AgentResultError):
        run(monkeypatch, InvalidResult(), [])
