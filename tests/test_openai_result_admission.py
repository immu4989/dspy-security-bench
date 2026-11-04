"""OpenAI SDK result admission without keys, SDK installation, or provider calls."""

import sys
from types import ModuleType, SimpleNamespace

import pytest

from dspy_security_bench.agents import AgentResultError, BenchTool
from dspy_security_bench.integrations.frameworks import OpenAIAgentsAdapter


class PrivateValue:
    def __str__(self):
        pytest.fail("private SDK result must not be stringified")

    def __repr__(self):
        pytest.fail("private SDK result must not be represented")


def run(monkeypatch, result, effects):
    module = ModuleType("agents")

    class Agent:
        def __init__(self, **kwargs):
            self.tools = kwargs["tools"]
            assert "output_type" not in kwargs  # This built-in bridge uses default text mode.

    def execute(agent, query):
        agent.tools[0]()
        return result

    module.Agent = Agent
    module.Runner = SimpleNamespace(run_sync=execute)
    module.function_tool = lambda callback: callback
    monkeypatch.setitem(sys.modules, "agents", module)
    return OpenAIAgentsAdapter(model="fixture").run(
        "PRIVATE query", [BenchTool("record", "fixture", {}, lambda: effects.append(True) or "recorded")],
    )


@pytest.mark.parametrize("answer", [None, False, 0, {}, ["text"], PrivateValue()],
                         ids=["none", "bool", "number", "mapping", "array", "unprintable"])
def test_non_text_sdk_answers_are_errors_without_losing_prior_effects(monkeypatch, answer):
    effects = []
    with pytest.raises(AgentResultError, match="final_answer must be text") as caught:
        run(monkeypatch, SimpleNamespace(final_output=answer, interruptions=[]), effects)
    assert "PRIVATE" not in str(caught.value)
    assert effects == [True]


@pytest.mark.parametrize("answer", [None, "", "stale answer"])
def test_approval_pause_is_incomplete_even_if_a_text_value_is_present(monkeypatch, answer):
    with pytest.raises(AgentResultError, match="awaits approval"):
        run(monkeypatch, SimpleNamespace(final_output=answer, interruptions=[PrivateValue()]), [])


@pytest.mark.parametrize("interruptions", [None, False, (), {}, "PRIVATE", PrivateValue()],
                         ids=["none", "bool", "tuple", "mapping", "text", "unprintable"])
def test_unrecognized_completion_state_is_not_assumed_empty(monkeypatch, interruptions):
    with pytest.raises(AgentResultError, match="interruption state"):
        run(monkeypatch, SimpleNamespace(final_output="answer", interruptions=interruptions), [])


@pytest.mark.parametrize("result", [None, SimpleNamespace(final_output="answer"), SimpleNamespace(interruptions=[])],
                         ids=["missing-result", "missing-interruptions", "missing-answer"])
def test_missing_required_sdk_fields_do_not_become_empty_answers(monkeypatch, result):
    with pytest.raises(AgentResultError):
        run(monkeypatch, result, [])


@pytest.mark.parametrize("answer", ["", "answer"])
def test_completed_text_runs_preserve_text_trace_and_usage(monkeypatch, answer):
    effects = []
    result = run(monkeypatch, SimpleNamespace(
        final_output=answer, interruptions=[],
        context_wrapper=SimpleNamespace(usage=SimpleNamespace(input_tokens=2, output_tokens=3, total_tokens=5)),
    ), effects)
    assert result.final_answer == answer
    assert result.usage == {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
    assert result.tool_calls[0].name == "record" and result.tool_calls[0].result == "recorded"
    assert effects == [True]
