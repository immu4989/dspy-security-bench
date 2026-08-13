"""Zero-network compatibility checks for optional native framework SDKs."""

from __future__ import annotations

import inspect
import os

import pytest

from dspy_security_bench.agents import BenchTool
from dspy_security_bench.integrations.frameworks import _tool_callable


def _tool():
    return BenchTool(
        name="lookup_record",
        description="Look up a synthetic record by identifier.",
        parameters={
            "type": "object",
            "properties": {"record_id": {"type": "string"}},
            "required": ["record_id"],
        },
        _call=lambda **kwargs: str(kwargs),
    )


def test_selected_framework_sdk_surface_is_compatible():
    framework = os.environ.get("DSB_FRAMEWORK")
    if not framework:
        pytest.skip("run by the optional-framework compatibility matrix")

    function = _tool_callable(_tool(), [])
    if framework == "openai-agents":
        from agents import Agent, Runner, function_tool

        native = function_tool(function)
        assert callable(Runner.run_sync)
        assert inspect.isclass(Agent)
        assert native.name == "lookup_record"
    elif framework == "langchain":
        from langchain.agents import create_agent
        from langchain_openai import ChatOpenAI

        assert callable(create_agent)
        assert inspect.isclass(ChatOpenAI)
    elif framework == "pydantic-ai":
        from pydantic_ai import Agent

        assert inspect.isclass(Agent)
        assert "tools" in inspect.signature(Agent).parameters
    elif framework == "crewai":
        from crewai import Agent
        from crewai.tools import tool

        native = tool("lookup_record")(function)
        assert inspect.isclass(Agent)
        assert native.name == "lookup_record"
    elif framework == "autogen":
        from autogen_agentchat.agents import AssistantAgent
        from autogen_ext.models.openai import OpenAIChatCompletionClient

        assert inspect.isclass(AssistantAgent)
        assert inspect.isclass(OpenAIChatCompletionClient)
    else:
        pytest.fail(f"unsupported DSB_FRAMEWORK value: {framework}")
