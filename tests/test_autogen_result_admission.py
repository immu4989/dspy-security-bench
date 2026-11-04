"""SDK-free tests for AutoGen configuration, attribution, and cleanup."""

import sys
from types import ModuleType, SimpleNamespace

import pytest

from dspy_security_bench.agents import AgentResultError, BenchTool
from dspy_security_bench.integrations import AutoGenAdapter


class PrivateValue:
    def __str__(self):
        pytest.fail("must not stringify private native state")

    def __repr__(self):
        pytest.fail("must not represent private native state")


def message(**changes):
    return SimpleNamespace(**{"type": "TextMessage", "source": "fixture_agent", "content": "answer"} | changes)


def result(**changes):
    return SimpleNamespace(**{"messages": [message()], "stop_reason": None} | changes)


def install_sdk(monkeypatch, returned, events):
    class Client:
        def __init__(self, **kwargs):
            events.append("client")
            assert kwargs["parallel_tool_calls"] is False

        async def close(self):
            events.append("closed")

    class Agent:
        def __init__(self, **kwargs):
            self.tools = kwargs["tools"]

        async def run(self, *, task):
            await self.tools[0]()
            return returned

    for name, attributes in (
        ("autogen_agentchat", {}), ("autogen_agentchat.agents", {"AssistantAgent": Agent}),
        ("autogen_ext", {}), ("autogen_ext.models", {}),
        ("autogen_ext.models.openai", {"OpenAIChatCompletionClient": Client}),
    ):
        module = ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)


def run(monkeypatch, returned, events):
    install_sdk(monkeypatch, returned, events)
    tool = BenchTool("record", "Synthetic action", {}, lambda: events.append("effect") or "recorded")
    return AutoGenAdapter(model="fixture", name="fixture_agent").run("PRIVATE query", [tool])


@pytest.mark.parametrize("answer", [None, 0, False, {}, [], PrivateValue()],
                         ids=["none", "number", "bool", "mapping", "array", "private"])
def test_non_text_output_is_not_coerced_after_native_cleanup(monkeypatch, answer):
    events = []
    with pytest.raises(AgentResultError, match="final_answer must be text") as caught:
        run(monkeypatch, result(messages=[message(content=answer)]), events)
    assert "PRIVATE" not in str(caught.value)
    assert events == ["client", "effect", "closed"]


@pytest.mark.parametrize("kind", ["HandoffMessage", "StopMessage", "ThoughtEvent", "ToolCallRequestEvent",
                                  "ToolCallExecutionEvent", "ModelClientStreamingChunkEvent", "StructuredMessage",
                                  "MultiModalMessage", None, [], PrivateValue()],
                         ids=["handoff", "stop", "thought", "request", "execution", "chunk", "structured",
                              "multimodal", "missing", "array", "private"])
def test_non_final_message_types_are_not_answers(monkeypatch, kind):
    events = []
    with pytest.raises(AgentResultError, match="terminal message"):
        run(monkeypatch, result(messages=[message(), message(type=kind)]), events)
    assert events == ["client", "effect", "closed"]


@pytest.mark.parametrize("source", [None, "user", "other_agent", False, {}, PrivateValue()],
                         ids=["missing", "user", "other-agent", "bool", "mapping", "private"])
def test_answer_must_be_attributed_to_selected_agent(monkeypatch, source):
    with pytest.raises(AgentResultError, match="source"):
        run(monkeypatch, result(messages=[message(source=source)]), [])


@pytest.mark.parametrize("state", [None, False, [], {}, (), "PRIVATE", PrivateValue()],
                         ids=["none", "bool", "empty-list", "mapping", "empty-tuple", "text", "private"])
def test_missing_or_invalid_message_sequence_is_an_error(monkeypatch, state):
    with pytest.raises(AgentResultError, match="message sequence"):
        run(monkeypatch, result(messages=state), [])


@pytest.mark.parametrize("reason", ["Maximum messages", "", False, {}, PrivateValue()],
                         ids=["termination", "empty-text", "bool", "mapping", "private"])
def test_team_termination_or_malformed_stop_state_is_not_single_agent_completion(monkeypatch, reason):
    with pytest.raises(AgentResultError, match="stop state"):
        run(monkeypatch, result(stop_reason=reason), [])


@pytest.mark.parametrize("state", [None, SimpleNamespace(), SimpleNamespace(messages=[message()]),
                                   SimpleNamespace(stop_reason=None),
                                   {"messages": [message()], "stop_reason": None}],
                         ids=["none", "empty", "missing-stop", "missing-messages", "serialized"])
def test_incomplete_envelopes_are_not_stringified(monkeypatch, state):
    with pytest.raises(AgentResultError):
        run(monkeypatch, state, [])


@pytest.mark.parametrize("kind", ["TextMessage", "ToolCallSummaryMessage"])
@pytest.mark.parametrize("answer", ["", "answer"])
@pytest.mark.parametrize("container", [list, tuple])
def test_supported_terminal_text_preserves_answer_and_executed_tools(monkeypatch, kind, answer, container):
    events = []
    returned = run(monkeypatch, result(messages=container([message(type=kind, content=answer)])), events)
    assert returned.final_answer == answer
    assert returned.tool_calls[0].name == "record" and returned.tool_calls[0].result == "recorded"
    assert events == ["client", "effect", "closed"]


@pytest.mark.parametrize("name", [None, 3, "", "autogen-agent", "1agent", "agent name", "user"])
def test_invalid_names_fail_before_any_sdk_client_is_constructed(monkeypatch, name):
    events = []
    install_sdk(monkeypatch, result(), events)
    with pytest.raises(ValueError, match="name"):
        AutoGenAdapter(name=name).run("query", [])
    assert events == []


@pytest.mark.parametrize("iterations", [None, True, False, 0, -1, 1.5, "2"])
def test_iteration_limit_requires_positive_nonboolean_integer(monkeypatch, iterations):
    events = []
    install_sdk(monkeypatch, result(), events)
    with pytest.raises(ValueError, match="max_tool_iterations"):
        AutoGenAdapter(max_tool_iterations=iterations).run("query", [])
    assert events == []


@pytest.mark.parametrize("field,value", [("name", "invalid name"), ("max_tool_iterations", False)])
def test_mutated_configuration_is_rechecked_before_client_construction(monkeypatch, field, value):
    events = []
    install_sdk(monkeypatch, result(), events)
    adapter = AutoGenAdapter()
    setattr(adapter, field, value)
    with pytest.raises(ValueError):
        adapter.run("query", [])
    assert events == []


def test_default_name_is_valid_for_native_agent():
    assert AutoGenAdapter().name == "autogen_agent"
