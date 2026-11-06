"""Actual Pydantic AI graph checks for source-schema transport and validation."""

import asyncio
import os
from copy import deepcopy

import pytest

from dspy_security_bench.agents import BenchTool
from dspy_security_bench.integrations import NativeToolSchemaError, PydanticAIAdapter

pytestmark = pytest.mark.skipif(os.environ.get("DSB_FRAMEWORK") != "pydantic-ai",
                                reason="optional Pydantic AI SDK matrix")


@pytest.fixture(autouse=True)
def offline_sdk(monkeypatch):
    attempts = []

    def denied(*args, **kwargs):
        attempts.append(True)
        pytest.fail("schema fixture must not contact providers or telemetry")

    monkeypatch.setattr("socket.socket.connect", denied)
    monkeypatch.setattr("socket.socket.connect_ex", denied)
    monkeypatch.setattr("socket.getaddrinfo", denied)
    from pydantic_ai import models

    monkeypatch.setattr(models, "ALLOW_MODEL_REQUESTS", False)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield
    finally:
        loop.close()
        asyncio.set_event_loop(None)
    assert not attempts


def schema():
    return {
        "type": "object", "additionalProperties": False,
        "description": "Synthetic order constraints", "x-audit": {"labels": ["synthetic"]},
        "properties": {
            "external-id": {"type": "string", "pattern": "^R-[0-9]+$"},
            "items": {"type": "array", "items": {"$ref": "#/$defs/item"}, "minItems": 1},
            "note": {"type": ["string", "null"]},
            "limit": {"type": "integer", "minimum": 1, "default": 2},
        },
        "required": ["external-id", "items", "note"],
        "$defs": {"item": {"type": "object", "additionalProperties": False,
                           "properties": {"mode": {"enum": ["read", "review"]},
                                          "count": {"type": "integer", "minimum": 1, "maximum": 3}},
                           "required": ["mode", "count"]}},
    }


def valid():
    return {"external-id": "R-1", "items": [{"mode": "read", "count": 1}], "note": None}


def runner(monkeypatch, tool, calls, *, mutate=None, repeat=False):
    from pydantic_ai import Agent
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    seen, captured, agents = [], [], []
    expected = deepcopy(tool.parameters) or {"type": "object", "properties": {}}

    async def model(messages, info):
        definition = info.function_tools[0]
        assert definition.name == tool.name
        assert definition.parameters_json_schema == expected
        index = len(seen)
        seen.append(messages)
        if mutate is not None and index == 0:
            mutate(tool)
        if index < len(calls) or repeat:
            argument = calls[min(index, len(calls) - 1)]
            return ModelResponse(parts=[ToolCallPart(tool.name, argument, tool_call_id=f"call-{index}")])
        return ModelResponse(parts=[TextPart("done")])

    def factory(*args, **kwargs):
        captured.extend(kwargs["tools"])
        result = Agent(*args, **kwargs)
        result.instrument = False
        agents.append(result)
        return result

    monkeypatch.setattr("pydantic_ai.Agent", factory)
    return PydanticAIAdapter(model=FunctionModel(model)), seen, captured, agents


@pytest.mark.parametrize("invalid", [
    {}, valid() | {"items": []}, valid() | {"items": [{"mode": "write", "count": 1}]},
    valid() | {"items": [{"mode": "read", "count": 4}]},
    valid() | {"items": [{"mode": "read", "count": True}]},
    valid() | {"items": [{"mode": "read", "count": "1"}]},
    valid() | {"items": [{"mode": "read", "count": 1, "PRIVATE": True}]},
    valid() | {"external-id": "PRIVATE"}, valid() | {"note": False}, valid() | {"limit": None},
], ids=["required", "array", "enum", "bounds", "bool", "coercion", "extra", "pattern", "nullable", "optional-null"])
def test_native_retry_corrects_arguments_before_live_callback(monkeypatch, invalid):
    from pydantic_ai.messages import RetryPromptPart, ToolReturnPart

    effects = []
    tool = BenchTool("record", "Synthetic order", schema(), lambda **kwargs: effects.append(kwargs) or "recorded")
    adapter, seen, _, _ = runner(monkeypatch, tool, [invalid, valid()])
    result = adapter.run("query", [tool])
    assert len(seen) == 3 and result.final_answer == "done"
    assert effects == [valid()]
    assert result.tool_calls[0].args == valid() and len(result.tool_calls) == 1
    assert any(isinstance(part, RetryPromptPart) for message in seen[1] for part in message.parts)
    retry = next(part for message in seen[1] for part in message.parts if isinstance(part, RetryPromptPart))
    assert "PRIVATE" not in str(retry.content)
    assert any(isinstance(part, ToolReturnPart) for message in seen[2] for part in message.parts)


def test_schema_is_frozen_per_run_and_callback_default_is_not_schema_default(monkeypatch):
    effects = []

    def action(limit=9):
        effects.append(limit)
        return "recorded"

    parameters = {"type": "object", "properties": {"limit": {"type": "integer", "default": 2}}}
    tool = BenchTool("record", "Synthetic default", parameters, action)
    adapter, _, captured, _ = runner(monkeypatch, tool, [{}], mutate=lambda tool: tool.parameters.clear())
    result = adapter.run("query", [tool])
    assert effects == [9]  # The original callback, not the adapter, owns defaults.
    assert result.tool_calls[0].args == {}
    assert tool.parameters == {}
    assert captured[0].tool_def.parameters_json_schema["properties"]["limit"]["default"] == 2


def test_retry_exhaustion_never_executes_callback(monkeypatch):
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    effects = []
    tool = BenchTool("record", "Synthetic action", schema(), lambda **kwargs: effects.append(kwargs) or "recorded")
    adapter, seen, _, _ = runner(monkeypatch, tool, [{}], repeat=True)
    with pytest.raises(UnexpectedModelBehavior):
        adapter.run("query", [tool])
    assert not effects and len(seen) >= 2


def test_unresolved_schema_reference_is_not_model_retry_feedback(monkeypatch):
    effects = []
    tool = BenchTool("record", "Synthetic action", {"type": "object", "$ref": "https://example.invalid/PRIVATE"},
                     lambda **kwargs: effects.append(kwargs) or "recorded")
    adapter, seen, _, _ = runner(monkeypatch, tool, [{}])
    with pytest.raises(NativeToolSchemaError, match="evaluated offline") as error:
        adapter.run("query", [tool])
    assert not effects and len(seen) == 1
    assert "PRIVATE" not in str(error.value)


def test_invalid_schema_fails_before_constructing_agent_or_requesting_model(monkeypatch):
    tool = BenchTool("record", "Synthetic action", {"type": "PRIVATE"}, lambda **kwargs: "unreachable")
    adapter, seen, _, agents = runner(monkeypatch, tool, [])
    with pytest.raises(NativeToolSchemaError):
        adapter.run("query", [tool])
    assert not seen and not agents


@pytest.mark.parametrize("name", ["self", "ctx", "func", "args", "kwargs", "config", "run_manager", "callbacks"])
def test_argument_names_do_not_collide_with_adapter_or_sdk_helpers(monkeypatch, name):
    effects = []
    values = {name: "synthetic"}
    tool = BenchTool("record", "Synthetic named argument", {
        "type": "object", "properties": {name: {"type": "string"}}, "required": [name],
    }, lambda **kwargs: effects.append(kwargs) or "recorded")
    adapter, _, _, _ = runner(monkeypatch, tool, [values])
    result = adapter.run("query", [tool])
    assert effects == [values] and result.tool_calls[0].args == values
