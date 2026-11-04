"""Framework-independent fixtures for LangChain final-answer attribution."""

import sys
from types import ModuleType, SimpleNamespace

import pytest

from dspy_security_bench.agents import AgentResultError, BenchTool
from dspy_security_bench.integrations.frameworks import LangChainAdapter, _langchain_output


class PrivateValue:
    def __str__(self):
        pytest.fail("private result data must not be stringified")

    def __repr__(self):
        pytest.fail("private result data must not be represented")


def message(**fields):
    return SimpleNamespace(**({"type": "ai", "content": "answer", "tool_calls": [], "invalid_tool_calls": []} | fields))


def output(final=None, **fields):
    return {"messages": [final if final is not None else message()], **fields}


@pytest.mark.parametrize("result", [None, "PRIVATE", PrivateValue(), {}, {"output": "PRIVATE"},
                                    {"messages": []}, {"messages": None}, {"messages": ()}],
                         ids=["none", "text", "object", "empty", "legacy-output", "empty-messages", "missing-messages", "tuple"])
def test_arbitrary_envelopes_do_not_become_final_answers(result):
    with pytest.raises(AgentResultError):
        _langchain_output(result)


@pytest.mark.parametrize("kind", [None, "human", "tool", "system", "chat", "AIMessageChunk"])
def test_only_terminal_assistant_messages_are_scored(kind):
    with pytest.raises(AgentResultError, match="assistant message"):
        _langchain_output({"messages": [message(content="stale assistant answer"), message(type=kind)]})


@pytest.mark.parametrize("pending", [None, False, {}, "PRIVATE", [PrivateValue()], (PrivateValue(),)],
                         ids=["none", "bool", "mapping", "text", "pending-list", "pending-tuple"])
def test_interruption_state_precedes_any_stale_answer(pending):
    with pytest.raises(AgentResultError, match="interruption state"):
        _langchain_output(output(__interrupt__=pending))


@pytest.mark.parametrize("field", ["tool_calls", "invalid_tool_calls"])
@pytest.mark.parametrize("calls", [None, False, (), {}, [PrivateValue()]],
                         ids=["none", "bool", "tuple", "mapping", "pending"])
def test_pending_or_malformed_tool_state_is_not_an_answer(field, calls):
    with pytest.raises(AgentResultError, match="tool calls"):
        _langchain_output(output(message(**{field: calls})))


@pytest.mark.parametrize("content", [None, {}, 0, [None], [PrivateValue()]],
                         ids=["none", "mapping", "number", "missing-block", "object-block"])
def test_unsupported_content_is_not_stringified(content):
    with pytest.raises(AgentResultError, match="unsupported content"):
        _langchain_output(output(message(content=content)))


@pytest.mark.parametrize("blocks", [None, (), [], [None], [{}], [{"type": "text", "text": None}],
                                   [{"type": "reasoning", "reasoning": PrivateValue()}],
                                   [{"type": "tool_call"}, {"type": "text", "text": "stale"}],
                                   [{"type": "tool_call_chunk"}], [{"type": "invalid_tool_call"}]],
                         ids=["none", "tuple", "empty", "missing", "untyped", "bad-text", "reasoning-only",
                              "pending-with-text", "chunk", "invalid-call"])
def test_block_content_requires_real_text_without_unfinished_tool_calls(blocks):
    with pytest.raises(AgentResultError):
        _langchain_output(output(message(content=[], content_blocks=blocks)))


def test_normalization_failure_has_fixed_diagnostics():
    class BrokenContent:
        type = "ai"
        content = []
        tool_calls = invalid_tool_calls = []

        @property
        def content_blocks(self):
            raise ValueError("PRIVATE SDK payload")

    with pytest.raises(AgentResultError, match="could not be normalized") as caught:
        _langchain_output(output(BrokenContent()))
    assert "PRIVATE" not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("text", ["", "answer"])
@pytest.mark.parametrize("pending", [[], ()])
def test_completed_plain_text_is_preserved(text, pending):
    assert _langchain_output(output(message(content=text), __interrupt__=pending)) == text


def test_text_blocks_concatenate_without_reasoning_metadata_or_invented_separators():
    blocks = [{"type": "reasoning", "reasoning": PrivateValue()}, {"type": "text", "text": "an"},
              {"type": "non_standard", "value": PrivateValue()}, {"type": "text", "text": "swer"}]
    assert _langchain_output(output(message(content=[], content_blocks=blocks))) == "answer"
    assert _langchain_output(output(message(content=[], content_blocks=[{"type": "text", "text": ""}]))) == ""


def test_adapter_rejects_paused_state_without_undoing_completed_tools(monkeypatch):
    effects = []

    def create_agent(**kwargs):
        def invoke(payload):
            kwargs["tools"][0]()
            return output(__interrupt__=(PrivateValue(),))
        return SimpleNamespace(invoke=invoke)

    module = ModuleType("langchain.agents")
    module.create_agent = create_agent
    monkeypatch.setitem(sys.modules, "langchain", ModuleType("langchain"))
    monkeypatch.setitem(sys.modules, "langchain.agents", module)
    with pytest.raises(AgentResultError, match="interruption"):
        LangChainAdapter(model="fixture").run("query", [BenchTool("record", "fixture", {}, lambda: effects.append(True) or "done")])
    assert effects == [True]
