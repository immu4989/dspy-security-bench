"""Pydantic AI text-mode result admission without optional SDK dependencies."""

import sys
from types import ModuleType, SimpleNamespace

import pytest

from dspy_security_bench.agents import AgentResultError, BenchTool
from dspy_security_bench.integrations import PydanticAIAdapter


class PrivateValue:
    def __str__(self):
        pytest.fail("structured or deferred output must not be stringified")

    def __repr__(self):
        pytest.fail("structured or deferred output must not be represented")


def run(monkeypatch, native_result, effects):
    class Agent:
        def __init__(self, model, *, tools, instructions):
            assert model == "fixture" and instructions.startswith("trusted")
            self.tools = tools

        def run_sync(self, query):
            assert query == "PRIVATE query"
            self.tools[0]()
            return native_result

    module = ModuleType("pydantic_ai")
    module.Agent = Agent
    monkeypatch.setitem(sys.modules, "pydantic_ai", module)
    return PydanticAIAdapter(model="fixture").run(
        "PRIVATE query", [BenchTool("record", "Synthetic action", {}, lambda: effects.append(True) or "recorded")],
        system_directive="trusted",
    )


@pytest.mark.parametrize("output", [None, False, 0, {}, ["answer"], {"approvals": ["pending"]}, PrivateValue()],
                         ids=["none", "bool", "number", "mapping", "array", "deferred-shape", "private"])
def test_non_text_output_never_becomes_answer_text(monkeypatch, output):
    effects = []
    with pytest.raises(AgentResultError, match="final_answer must be text") as captured:
        run(monkeypatch, SimpleNamespace(output=output), effects)
    assert "PRIVATE" not in str(captured.value)
    assert effects == [True]


@pytest.mark.parametrize("native_result", [None, SimpleNamespace(), {"output": "answer"}, "answer"],
                         ids=["none", "missing-output", "serialized", "raw-text"])
def test_missing_native_output_is_not_an_empty_answer(monkeypatch, native_result):
    with pytest.raises(AgentResultError, match="final_answer must be text"):
        run(monkeypatch, native_result, [])


@pytest.mark.parametrize("answer", ["", "answer"])
@pytest.mark.parametrize("callable_usage", [False, True])
def test_completed_text_preserves_trace_and_native_usage(monkeypatch, answer, callable_usage):
    usage = SimpleNamespace(input_tokens=2, output_tokens=3, total_tokens=5, requests=1)
    native = SimpleNamespace(output=answer, usage=(lambda: usage) if callable_usage else usage)
    effects = []
    result = run(monkeypatch, native, effects)
    assert result.final_answer == answer
    assert result.usage == {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5, "requests": 1}
    assert result.tool_calls[0].name == "record" and result.tool_calls[0].result == "recorded"
    assert effects == [True]


def test_invalid_output_is_rejected_before_optional_usage_access(monkeypatch):
    class InvalidResult:
        output = None

        @property
        def usage(self):
            pytest.fail("usage must not be inspected before required result admission")

    with pytest.raises(AgentResultError):
        run(monkeypatch, InvalidResult(), [])
