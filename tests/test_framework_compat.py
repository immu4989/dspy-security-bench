"""Zero-network compatibility checks for optional native framework SDKs."""

from __future__ import annotations

import inspect
import os

import pytest

from dspy_security_bench.agents import BenchTool
from dspy_security_bench.causal.runtime import (
    CausalRuntimeSession,
    LangGraphCausalCallback,
    OpenAIAgentsCausalProcessor,
)
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


def _runtime_session(**kwargs):
    return CausalRuntimeSession(
        scenario_id="framework-compatibility",
        title="Fictional framework compatibility",
        description="Synthetic zero-network compatibility fixture.",
        invariants=["scope_attenuation"],
        **kwargs,
    )


def _grant():
    return {
        "id": "grant",
        "kind": "grant",
        "actor": "identity",
        "authority_id": "authority-1",
        "subject": "agent",
        "resource": "record-1",
        "scopes": ["read"],
        "audience": "tool",
    }


def _exchange():
    return {
        "id": "exchange",
        "kind": "token_exchange",
        "actor": "token-service",
        "token_id": "token-1",
        "authority_id": "authority-1",
        "subject": "agent",
        "resource": "record-1",
        "scopes": ["read"],
        "audience": "tool",
    }


def test_selected_framework_sdk_surface_is_compatible():
    framework = os.environ.get("DSB_FRAMEWORK")
    if not framework:
        pytest.skip("run by the optional-framework compatibility matrix")

    function = _tool_callable(_tool(), [])
    if framework == "openai-agents":
        from agents import Agent, Runner, custom_span, function_tool, trace
        from agents.tracing import TracingProcessor, set_trace_processors

        native = function_tool(function)
        assert callable(Runner.run_sync)
        assert inspect.isclass(Agent)
        assert native.name == "lookup_record"
        session = _runtime_session()
        processor = OpenAIAgentsCausalProcessor(session)
        assert isinstance(processor, TracingProcessor)
        set_trace_processors([processor])
        with trace("causalproof-compatibility"):
            with custom_span("grant", data={"ignored": "content"}) as grant_span:
                processor.bind_span(grant_span, _grant())
                with custom_span("exchange", data={"ignored": "content"}) as exchange_span:
                    processor.bind_span(exchange_span, _exchange())
        structural, manifest = session.build()
        assert len(structural["resourceSpans"][0]["scopeSpans"][0]["spans"]) == 2
        assert len(manifest["bindings"]) == 2
    elif framework == "langchain":
        from langchain.agents import create_agent
        from langchain_core.callbacks import BaseCallbackHandler
        from langchain_openai import ChatOpenAI
        from langgraph.graph import END, START, StateGraph

        assert callable(create_agent)
        assert inspect.isclass(ChatOpenAI)
        session = _runtime_session(
            asserted_edges=[
                {
                    "before": "grant",
                    "after": "exchange",
                    "rationale": "The compiled compatibility graph declares this edge.",
                }
            ]
        )
        callback = LangGraphCausalCallback(
            session, node_events={"authorize": _grant(), "exchange": _exchange()}
        )
        assert isinstance(callback, BaseCallbackHandler)
        graph = (
            StateGraph(dict)
            .add_node("authorize", lambda state: state)
            .add_node("exchange", lambda state: state)
            .add_edge(START, "authorize")
            .add_edge("authorize", "exchange")
            .add_edge("exchange", END)
            .compile()
        )
        graph.invoke({}, config={"callbacks": [callback]})
        structural, manifest = session.build()
        assert len(structural["resourceSpans"][0]["scopeSpans"][0]["spans"]) == 2
        assert len(manifest["bindings"]) == 2
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
