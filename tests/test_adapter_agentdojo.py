"""Tests for adapters.agentdojo — serialization helpers + end-to-end task flow."""
from __future__ import annotations

import json
import types

import dspy
import pytest

from dspy_security_bench.adapters import DSPyReActV2Element
from dspy_security_bench.adapters.agentdojo import (
    _serialize_result,
    _tool_call_to_function_call,
)


# ---------------------------------------------------------------------------
# _serialize_result
# ---------------------------------------------------------------------------

def test_serialize_none_returns_empty():
    assert _serialize_result(None, None) == ""


def test_serialize_error_prefixes_with_marker():
    out = _serialize_result(None, "ValueError: bad input")
    assert out.startswith("[error]")
    assert "ValueError" in out


def test_serialize_str_passthrough():
    assert _serialize_result("hello", None) == "hello"


def test_serialize_numeric_to_str():
    assert _serialize_result(42, None) == "42"
    assert _serialize_result(3.14, None) == "3.14"
    assert _serialize_result(True, None) == "True"


def test_serialize_dict_to_json():
    out = _serialize_result({"a": 1, "b": "x"}, None)
    parsed = json.loads(out)
    assert parsed == {"a": 1, "b": "x"}


def test_serialize_list_of_dicts_to_json():
    out = _serialize_result([{"a": 1}, {"a": 2}], None)
    parsed = json.loads(out)
    assert parsed == [{"a": 1}, {"a": 2}]


def test_serialize_pydantic_model():
    import pydantic

    class Item(pydantic.BaseModel):
        name: str
        value: int

    out = _serialize_result(Item(name="x", value=5), None)
    parsed = json.loads(out)
    assert parsed == {"name": "x", "value": 5}


# ---------------------------------------------------------------------------
# _tool_call_to_function_call
# ---------------------------------------------------------------------------

def test_tool_call_to_function_call_translates_fields():
    tc = types.SimpleNamespace(name="search", args={"q": "foo"}, id="call_x_0")
    fc = _tool_call_to_function_call(tc)
    assert fc.function == "search"
    assert fc.args == {"q": "foo"}
    assert fc.id == "call_x_0"


def test_tool_call_to_function_call_handles_none_args():
    tc = types.SimpleNamespace(name="ping", args=None, id="call_x_0")
    fc = _tool_call_to_function_call(tc)
    assert fc.args == {}


# ---------------------------------------------------------------------------
# DSPyReActV2Element — end-to-end against a real AgentDojo user task
# ---------------------------------------------------------------------------

def test_user_task_0_passes_utility_with_canned_responses(
    workspace_suite, workspace_runtime, workspace_env
):
    task = workspace_suite.user_tasks["user_task_0"]

    lm = dspy.utils.DummyLM([
        {
            "next_thought": "Search calendar.",
            "tool_calls": dspy.ToolCalls.from_dict_list([
                {"name": "search_calendar_events",
                 "args": {"query": "Networking event", "date": "2024-05-26"}}
            ]),
        },
        {
            "next_thought": "Submit.",
            "tool_calls": dspy.ToolCalls.from_dict_list([
                {"name": "submit",
                 "args": {"answer": ("emma.johnson@bluesparrowtech.com, "
                                     "networking.participants@industry-network.com, "
                                     "alex.williams@mainsail-tech.com")}}
            ]),
        },
    ])

    def make_agent(tools, max_iters):
        return dspy.ReActV2("query -> answer", tools=tools, max_iters=max_iters)

    element = DSPyReActV2Element(make_agent)

    with dspy.context(lm=lm, adapter=dspy.ChatAdapter()):
        _q, _r, _e, out_messages, _x = element.query(
            query=task.PROMPT,
            runtime=workspace_runtime,
            env=workspace_env,
            messages=[],
            extra_args={},
        )

    final = out_messages[-1]
    final_text = " ".join(c.get("content", "") for c in (final.get("content") or []))

    ok = task.utility(
        model_output=final_text,
        pre_environment=workspace_env,
        post_environment=workspace_env,
        strict=False,
    )
    assert ok


def test_multi_output_signature_raises(workspace_suite, workspace_runtime, workspace_env):
    """v0.1 constraint: signature must have exactly one output field."""
    lm = dspy.utils.DummyLM([
        {"next_thought": "x", "tool_calls": dspy.ToolCalls.from_dict_list([
            {"name": "submit", "args": {"answer": "x", "confidence": "high"}},
        ])},
    ])

    def make_multi_output_agent(tools, max_iters):
        return dspy.ReActV2(
            "query -> answer, confidence",
            tools=tools,
            max_iters=max_iters,
        )

    element = DSPyReActV2Element(make_multi_output_agent)
    with dspy.context(lm=lm, adapter=dspy.ChatAdapter()):
        with pytest.raises(ValueError, match="single output field"):
            element.query(
                query="x",
                runtime=workspace_runtime,
                env=workspace_env,
                messages=[],
                extra_args={},
            )
