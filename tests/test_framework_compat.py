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


@pytest.mark.skipif(os.environ.get("DSB_FRAMEWORK") != "openai-agents", reason="optional OpenAI SDK matrix")
@pytest.mark.parametrize("mode", ["answer", "empty", "approval"])
def test_openai_bridge_runs_native_sdk_loop_without_provider_calls(monkeypatch, mode):
    from agents import Model, ModelResponse, RunConfig, Runner, Usage
    from openai.types.responses import (
        ResponseFunctionToolCall,
        ResponseOutputMessage,
        ResponseOutputText,
    )

    from dspy_security_bench.agents import AgentResultError
    from dspy_security_bench.integrations.frameworks import OpenAIAgentsAdapter

    def no_network(*args, **kwargs):
        pytest.fail("native compatibility fixture must not contact providers or tracing services")

    monkeypatch.setattr("socket.socket.connect", no_network)
    monkeypatch.setattr("socket.socket.connect_ex", no_network)
    monkeypatch.setattr("socket.getaddrinfo", no_network)

    class CannedModel(Model):
        calls = 0

        async def get_response(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 1:
                output = [ResponseFunctionToolCall(type="function_call", name="record",
                                                  call_id="fixture-call", arguments="{}")]
            else:
                output = [ResponseOutputMessage(type="message", id="fixture-message", role="assistant",
                                               status="completed", content=[ResponseOutputText(
                                                   type="output_text", text="" if mode == "empty" else "done", annotations=[])])]
            return ModelResponse(output=output, usage=Usage(requests=1, input_tokens=2, output_tokens=3, total_tokens=5),
                                 response_id=None)

        def stream_response(self, *args, **kwargs):
            pytest.fail("this adapter uses non-streaming runs")

    native_run = Runner.run_sync
    captured, effects = [], []

    def offline_run(agent, query):
        if mode == "approval":
            agent.tools[0].needs_approval = True
        result = native_run(agent, query, run_config=RunConfig(tracing_disabled=True))
        captured.append(result)
        return result

    monkeypatch.setattr(Runner, "run_sync", staticmethod(offline_run))
    model = CannedModel()
    adapter = OpenAIAgentsAdapter(model=model)
    tool = BenchTool("record", "Record a fictional action.", {"type": "object", "properties": {}},
                     lambda: effects.append(True) or "recorded")
    if mode == "approval":
        with pytest.raises(AgentResultError, match="awaits approval"):
            adapter.run("fixture", [tool])
        assert effects == [] and model.calls == 1
        assert captured[0].interruptions
    else:
        result = adapter.run("fixture", [tool])
        assert result.final_answer == ("" if mode == "empty" else "done")
        assert result.tool_calls[0].result == "recorded"
        assert effects == [True] and model.calls == 2
        assert result.usage["total_tokens"] == 10
        assert captured[0].interruptions == []


@pytest.mark.skipif(os.environ.get("DSB_FRAMEWORK") != "langchain", reason="optional LangChain SDK matrix")
@pytest.mark.parametrize("mode", ["answer", "empty", "blocks", "approval", "static-pause"])
def test_langchain_bridge_runs_native_agent_loop_without_provider_calls(monkeypatch, mode):
    from types import SimpleNamespace

    from langchain.agents import create_agent
    from langchain.agents.middleware import HumanInTheLoopMiddleware
    from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
    from langchain_core.messages import AIMessage
    from langgraph.checkpoint.memory import InMemorySaver
    from langsmith import tracing_context

    from dspy_security_bench.agents import AgentResultError
    from dspy_security_bench.integrations.frameworks import LangChainAdapter

    def no_network(*args, **kwargs):
        pytest.fail("native compatibility fixture must not contact providers or tracing services")

    monkeypatch.setattr("socket.socket.connect", no_network)
    monkeypatch.setattr("socket.socket.connect_ex", no_network)
    monkeypatch.setattr("socket.getaddrinfo", no_network)

    class CannedModel(FakeMessagesListChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

    content = "" if mode == "empty" else "done"
    if mode == "blocks":
        content = [{"type": "reasoning", "reasoning": "PRIVATE"},
                   {"type": "text", "text": "do"}, {"type": "text", "text": "ne"}]
    model = CannedModel(responses=[
        AIMessage(content="", tool_calls=[{"name": "record", "args": {}, "id": "fixture-call", "type": "tool_call"}]),
        AIMessage(content=content),
    ])
    captured, effects = [], []

    def native_create(**kwargs):
        options = {}
        if mode == "approval":
            options["middleware"] = [HumanInTheLoopMiddleware(interrupt_on={"record": True})]
            options["checkpointer"] = InMemorySaver()
        elif mode == "static-pause":
            options["interrupt_before"] = ["tools"]
            options["checkpointer"] = InMemorySaver()
        graph = create_agent(**kwargs, **options)

        def invoke(payload):
            with tracing_context(enabled=False):
                result = graph.invoke(payload, config={"configurable": {"thread_id": "fixture"}})
            captured.append(result)
            return result

        return SimpleNamespace(invoke=invoke)

    monkeypatch.setattr("langchain.agents.create_agent", native_create)
    tool = BenchTool("record", "Record a fictional action.", {"type": "object", "properties": {}},
                     lambda: effects.append(True) or "recorded")
    adapter = LangChainAdapter(model=model)
    if mode in {"approval", "static-pause"}:
        with pytest.raises(AgentResultError):
            adapter.run("fixture", [tool])
        assert effects == []
        if mode == "approval":
            assert captured[0]["__interrupt__"]
        else:
            assert captured[0]["messages"][-1].tool_calls
    else:
        result = adapter.run("fixture", [tool])
        assert result.final_answer == ("" if mode == "empty" else "done")
        assert effects == [True] and result.tool_calls[0].result == "recorded"
        assert captured[0]["messages"][-1].type == "ai"


@pytest.mark.skipif(os.environ.get("DSB_FRAMEWORK") != "langchain", reason="optional LangChain SDK matrix")
def test_langchain_native_message_types_cannot_substitute_for_final_assistant_text():
    from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage, ToolMessage

    from dspy_security_bench.agents import AgentResultError
    from dspy_security_bench.integrations.frameworks import _langchain_output

    for message in (HumanMessage(content="PRIVATE user text"), ToolMessage(content="PRIVATE tool data", tool_call_id="fixture"),
                    AIMessageChunk(content="partial"), AIMessage(content_blocks=[{"type": "reasoning", "reasoning": "PRIVATE"}])):
        with pytest.raises(AgentResultError):
            _langchain_output({"messages": [message]})
    message = AIMessage(content_blocks=[{"type": "reasoning", "reasoning": "PRIVATE"}, {"type": "text", "text": ""}])
    assert _langchain_output({"messages": [message]}) == ""
