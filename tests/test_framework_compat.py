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


@pytest.fixture(autouse=True)
def isolated_crewai_sdk(monkeypatch, tmp_path):
    """Disable optional SDK egress before its first import, not just model calls."""
    if os.environ.get("DSB_FRAMEWORK") != "crewai":
        yield
        return
    monkeypatch.setenv("CREWAI_DISABLE_TELEMETRY", "true")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    monkeypatch.setenv("CREWAI_TRACING_ENABLED", "false")
    monkeypatch.setenv("CREWAI_DISABLE_VERSION_CHECK", "true")
    monkeypatch.setenv("CREWAI_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.chdir(tmp_path)
    attempted_connections = []

    def no_network(*args, **kwargs):
        attempted_connections.append(True)
        pytest.fail("native CrewAI fixture must not contact providers or telemetry services")

    monkeypatch.setattr("socket.socket.connect", no_network)
    monkeypatch.setattr("socket.socket.connect_ex", no_network)
    monkeypatch.setattr("socket.getaddrinfo", no_network)
    yield
    assert not attempted_connections, "CrewAI attempted network access, even if its SDK caught the error"


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


@pytest.fixture
def native_sync_loop():
    """Own the loop used by SDK run_sync instead of leaving an implicit loop open."""
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()
        asyncio.set_event_loop(None)


@pytest.mark.skipif(os.environ.get("DSB_FRAMEWORK") != "crewai", reason="optional CrewAI SDK matrix")
@pytest.mark.parametrize("inside_loop", [False, True])
@pytest.mark.parametrize("mode", ["answer", "tool", "react-tool", "error-after-tool", "empty-response", "tool-invalid", "tool-error"])
def test_crewai_bridge_runs_native_sdk_loop_without_provider_calls(monkeypatch, tmp_path, mode, inside_loop):
    import asyncio
    from contextvars import ContextVar
    from copy import deepcopy
    from pathlib import Path

    from crewai import Agent, BaseLLM
    from crewai.lite_agent_output import LiteAgentOutput
    from crewai_core.paths import db_storage_path

    from dspy_security_bench.agents import AgentResultError
    from dspy_security_bench.integrations import CrewAIAdapter, NativeToolExecutionError

    assert Path(db_storage_path()) == tmp_path / "storage"
    calls, captured, agents, effects, returned_awaitables = [], [], [], [], []
    request = ContextVar("native-crewai-request", default="missing")
    tool_mode = mode in {"tool", "react-tool", "error-after-tool", "tool-invalid", "tool-error"}

    class CannedLLM(BaseLLM):
        def supports_function_calling(self):
            return mode != "react-tool"

        def call(self, messages, tools=None, available_functions=None, **kwargs):
            assert request.get() == "request-1"
            assert available_functions is None  # Execution belongs to the SDK, not this fixture.
            calls.append(deepcopy(messages))
            self._track_token_usage_internal({"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5})
            if mode == "empty-response":
                return ""
            if tool_mode and len(calls) % 2 == 1:
                if mode == "react-tool":
                    return 'Thought: record the action\nAction: record\nAction Input: {"record_id":"R-1"}'
                # CrewAI's strict provider schema marks even defaulted fields
                # required. Its local tool validator still supplies defaults.
                assert "record_id" in tools[0]["function"]["parameters"]["required"]
                assert tools[0]["function"]["parameters"]["properties"]["limit"]["type"] == "integer"
                return [{"id": "fixture-call", "type": "function", "function": {
                    "name": "record", "arguments": '{"record_id":"R-1"}',
                }}]
            if mode == "error-after-tool":
                raise LookupError("synthetic model failure after a tool effect")
            return "Final Answer: done" if mode == "react-tool" else "done"

        async def acall(self, *args, **kwargs):
            await asyncio.sleep(0)
            return self.call(*args, **kwargs)

    class CapturingAgent(Agent):
        def kickoff(self, *args, **kwargs):
            result = super().kickoff(*args, **kwargs)
            returned_awaitables.append(inspect.isawaitable(result))
            if inspect.isawaitable(result):
                async def capture():
                    output = await result
                    captured.append(output)
                    return output
                return capture()
            captured.append(result)
            return result

    def agent_factory(**kwargs):
        schema = kwargs["tools"][0].args_schema.model_json_schema()
        assert schema["required"] == ["record_id"]
        assert schema["properties"]["limit"]["default"] == 1
        agent = CapturingAgent(**kwargs)
        agents.append(agent)
        return agent

    monkeypatch.setattr("crewai.Agent", agent_factory)
    model = CannedLLM(model="fixture/no-provider")
    adapter = CrewAIAdapter(model=model, name="fixture role")

    def record(**kwargs):
        effects.append(kwargs)
        if mode == "tool-error":
            raise LookupError("synthetic tool callback failure")
        return None if mode == "tool-invalid" else "recorded"

    tool = BenchTool("record", "Record a fictional action.", {
        "type": "object", "properties": {"record_id": {"type": "string"}, "limit": {"type": "integer", "default": 1}},
        "required": ["record_id"],
    }, record)

    def invoke(query):
        token = request.set("request-1")
        try:
            return adapter.run(query, [tool], system_directive="trusted synthetic directive")
        finally:
            request.reset(token)

    async def invoke_inside_loop(query):
        return invoke(query)

    def run(query):
        return asyncio.run(invoke_inside_loop(query)) if inside_loop else invoke(query)

    if mode in {"tool-invalid", "tool-error"}:
        with pytest.raises(AgentResultError if mode == "tool-invalid" else NativeToolExecutionError):
            run("first request")
        assert effects == [{"record_id": "R-1", "limit": 1}]
        assert captured[0].raw == "done"  # Native recovery does not certify the supplied callback.
        return

    if mode in {"error-after-tool", "empty-response"}:
        error = LookupError if mode == "error-after-tool" else ValueError
        with pytest.raises(error):
            run("first request")
        assert effects == ([{"record_id": "R-1", "limit": 1}] if tool_mode else [])
        assert captured == []
        return

    for query in ("first request", "second request"):
        result = run(query)
        assert result.final_answer == "done"
        assert len(result.tool_calls) == int(tool_mode)
        if tool_mode:
            assert result.tool_calls[0].args == {"record_id": "R-1", "limit": 1}
            assert result.tool_calls[0].result == "recorded"
        multiplier = 2 if tool_mode else 1
        assert result.usage == {"prompt_tokens": 2 * multiplier, "completion_tokens": 3 * multiplier,
                                "total_tokens": 5 * multiplier}
        assert isinstance(captured[-1], LiteAgentOutput)
        assert captured[-1].agent_role == "fixture role" and captured[-1].raw == "done"
    assert returned_awaitables == [inside_loop, inside_loop]
    assert len(agents) == 2 and agents[0] is not agents[1]
    assert len(calls) == (4 if tool_mode else 2)
    assert "first request" not in str(calls[2 if tool_mode else 1])
    assert effects == ([{"record_id": "R-1", "limit": 1}] * 2 if tool_mode else [])
    assert request.get() == "missing"


@pytest.mark.skipif(os.environ.get("DSB_FRAMEWORK") != "pydantic-ai", reason="optional Pydantic AI SDK matrix")
@pytest.mark.parametrize("mode", ["answer", "tool", "approval", "deferred", "structured", "empty-response", "tool-invalid", "tool-retry"])
def test_pydantic_bridge_runs_native_sdk_loop_without_provider_calls(monkeypatch, native_sync_loop, mode):
    from pydantic import BaseModel
    from pydantic_ai import Agent, CallDeferred, DeferredToolRequests, ModelRetry, models
    from pydantic_ai.exceptions import UnexpectedModelBehavior
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, UserPromptPart
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.usage import RequestUsage

    from dspy_security_bench.agents import AgentResultError
    from dspy_security_bench.integrations import NativeToolExecutionError, PydanticAIAdapter

    def no_network(*args, **kwargs):
        pytest.fail("native Pydantic AI fixture must not contact providers or tracing services")

    monkeypatch.setattr("socket.socket.connect", no_network)
    monkeypatch.setattr("socket.socket.connect_ex", no_network)
    monkeypatch.setattr("socket.getaddrinfo", no_network)
    monkeypatch.setattr(models, "ALLOW_MODEL_REQUESTS", False)
    calls, captured, agents, effects = [], [], [], []

    class StructuredAnswer(BaseModel):
        answer: str

    async def model_function(messages, info):
        calls.append(messages)
        if mode == "empty-response":
            parts = []
        elif mode == "structured":
            parts = [ToolCallPart(info.output_tools[0].name, {"answer": "PRIVATE structured answer"})]
        elif mode in {"tool", "approval", "deferred", "tool-invalid", "tool-retry"} and len(calls) % 2 == 1:
            parts = [ToolCallPart("record", {"record_id": "R-1"}, tool_call_id="fixture-call")]
            if mode == "approval":
                parts.insert(0, TextPart("PRIVATE stale answer alongside an unapproved call"))
        else:
            parts = [TextPart("done")]
        return ModelResponse(parts=parts, usage=RequestUsage(input_tokens=2, output_tokens=3))

    class CapturingAgent(Agent):
        def run_sync(self, *args, **kwargs):
            result = super().run_sync(*args, **kwargs)
            captured.append(result)
            return result

    def agent_factory(*args, **kwargs):
        if mode in {"approval", "deferred"}:
            kwargs["output_type"] = [str, DeferredToolRequests]
        if mode == "approval":
            for tool in kwargs["tools"]:
                tool.requires_approval = True
        elif mode == "structured":
            kwargs["output_type"] = StructuredAnswer
        agent = CapturingAgent(*args, **kwargs)
        agent.instrument = False
        agents.append(agent)
        return agent

    monkeypatch.setattr("pydantic_ai.Agent", agent_factory)

    def record(**kwargs):
        if mode == "deferred":
            raise CallDeferred(metadata={"synthetic": True})
        effects.append(kwargs)
        if mode == "tool-retry":
            raise ModelRetry("synthetic callback failure represented as model retry")
        return None if mode == "tool-invalid" else "recorded"

    tool = BenchTool("record", "Record a fictional action.", {
        "type": "object", "properties": {"record_id": {"type": "string"}, "limit": {"type": "integer", "default": 1}},
        "required": ["record_id"],
    }, record)
    adapter = PydanticAIAdapter(model=FunctionModel(model_function))
    if mode in {"tool-invalid", "tool-retry"}:
        with pytest.raises(AgentResultError if mode == "tool-invalid" else NativeToolExecutionError):
            adapter.run("fixture", [tool])
        assert effects == [{"record_id": "R-1"}]
        if mode == "tool-retry":
            assert captured[0].output == "done"
    elif mode in {"approval", "deferred", "structured"}:
        with pytest.raises(AgentResultError, match="final_answer must be text"):
            adapter.run("fixture", [tool])
        assert not effects and len(calls) == 1
        if mode == "structured":
            assert isinstance(captured[0].output, StructuredAnswer)
        else:
            assert isinstance(captured[0].output, DeferredToolRequests)
            assert len(getattr(captured[0].output, "approvals" if mode == "approval" else "calls")) == 1
    elif mode == "empty-response":
        with pytest.raises(UnexpectedModelBehavior):
            adapter.run("fixture", [tool])
        assert not captured and not effects
    else:
        result = adapter.run("fixture", [tool])
        assert result.final_answer == "done"
        multiplier = 2 if mode == "tool" else 1
        assert result.usage == {"prompt_tokens": 2 * multiplier, "completion_tokens": 3 * multiplier,
                                "total_tokens": 5 * multiplier, "requests": multiplier}
        if mode == "tool":
            assert effects == [{"record_id": "R-1"}]
            assert result.tool_calls[0].args == effects[0]
            assert result.tool_calls[0].result == "recorded"
            second = adapter.run("second fixture", [tool])
            assert len(second.tool_calls) == 1 and len(effects) == 2
            assert len(agents) == 2 and agents[0] is not agents[1]
            assert [part.content for message in calls[2] for part in message.parts
                    if isinstance(part, UserPromptPart)] == ["second fixture"]
        else:
            assert not effects and not result.tool_calls


@pytest.mark.skipif(os.environ.get("DSB_FRAMEWORK") != "autogen", reason="optional AutoGen SDK matrix")
@pytest.mark.parametrize("mode", ["answer", "empty", "tool", "tool-limit", "handoff", "error", "tool-invalid", "tool-error"])
def test_autogen_bridge_runs_native_sdk_loop_without_provider_calls(monkeypatch, mode):
    from autogen_agentchat.agents import AssistantAgent
    from autogen_core import FunctionCall
    from autogen_core.models import CreateResult, RequestUsage
    from autogen_ext.models.replay import ReplayChatCompletionClient

    from dspy_security_bench.agents import AgentResultError
    from dspy_security_bench.integrations import AutoGenAdapter, NativeToolExecutionError

    def no_network(*args, **kwargs):
        pytest.fail("native AutoGen fixture must not contact providers or tracing services")

    monkeypatch.setattr("socket.socket.connect", no_network)
    monkeypatch.setattr("socket.socket.connect_ex", no_network)
    monkeypatch.setattr("socket.getaddrinfo", no_network)
    calls = CreateResult(
        finish_reason="function_calls", cached=False, usage=RequestUsage(prompt_tokens=2, completion_tokens=3),
        content=[FunctionCall(id="fixture-call", name="transfer_to_reviewer" if mode == "handoff" else "record",
                              arguments='{}' if mode == "handoff" else '{"record_id": "R-1"}')],
    )
    finish = CreateResult(finish_reason="stop", cached=False, content="" if mode == "empty" else "done",
                          usage=RequestUsage(prompt_tokens=4, completion_tokens=5))
    responses = {
        "answer": [finish], "empty": [finish], "tool": [calls, finish],
        "tool-limit": [calls], "handoff": [calls], "error": [],
        "tool-invalid": [calls, finish], "tool-error": [calls, finish],
    }[mode]
    clients, captured, effects, closed = [], [], [], []

    class Client(ReplayChatCompletionClient):
        async def close(self):
            closed.append(True)
            await super().close()

    def client_factory(**kwargs):
        assert kwargs == {"model": "fixture", "parallel_tool_calls": False}
        client = Client(responses, model_info={
            "vision": False, "function_calling": True, "json_output": False,
            "family": "unknown", "structured_output": False,
        })
        clients.append(client)
        return client

    class Agent(AssistantAgent):
        async def run(self, **kwargs):
            result = await super().run(**kwargs)
            captured.append(result)
            return result

    def agent_factory(**kwargs):
        if mode == "handoff":
            kwargs["handoffs"] = ["reviewer"]
        return Agent(**kwargs)

    monkeypatch.setattr("autogen_ext.models.openai.OpenAIChatCompletionClient", client_factory)
    monkeypatch.setattr("autogen_agentchat.agents.AssistantAgent", agent_factory)

    def record(**kwargs):
        effects.append(kwargs)
        if mode == "tool-error":
            raise LookupError("synthetic tool callback failure")
        return None if mode == "tool-invalid" else "recorded"

    tool = BenchTool("record", "Record a fictional action.", {
        "type": "object", "properties": {"record_id": {"type": "string"}, "limit": {"type": "integer", "default": 1}},
        "required": ["record_id"],
    }, record)
    adapter = AutoGenAdapter(model="fixture", max_tool_iterations=1 if mode == "tool-limit" else 10)
    if mode in {"tool-invalid", "tool-error"}:
        with pytest.raises(AgentResultError if mode == "tool-invalid" else NativeToolExecutionError):
            adapter.run("fixture", [tool])
        assert effects == [{"record_id": "R-1", "limit": 1}]
        assert captured[0].messages[-1].content == "done"
    elif mode == "handoff":
        with pytest.raises(AgentResultError, match="terminal message"):
            adapter.run("fixture", [tool])
        assert captured[0].messages[-1].type == "HandoffMessage"
        assert not effects
    elif mode == "error":
        with pytest.raises(ValueError, match="No more mock responses"):
            adapter.run("fixture", [tool])
        assert not effects and not captured
    else:
        result = adapter.run("fixture", [tool])
        assert result.final_answer == {"empty": "", "tool-limit": "recorded"}.get(mode, "done")
        # Replay computes its own prompt counts rather than using CreateResult's
        # prompt_tokens. Verify the client counters, not message-level receipts.
        prompt_count = sum(clients[0].count_tokens(call["messages"]) for call in clients[0].create_calls)
        assert result.usage == {
            "prompt_tokens": prompt_count,
            "completion_tokens": {"tool": 8, "tool-limit": 3}.get(mode, 5),
        }
        assert captured[0].stop_reason is None
        if mode in {"tool", "tool-limit"}:
            assert effects == [{"record_id": "R-1", "limit": 1}]
            assert result.tool_calls[0].args == effects[0]
            assert result.tool_calls[0].result == "recorded"
        else:
            assert effects == [] and result.tool_calls == []
    assert closed == [True] and len(clients) == 1
    assert len(clients[0].create_calls) == {"tool": 2, "tool-invalid": 2, "tool-error": 2, "error": 0}.get(mode, 1)
    if mode == "tool":
        second = adapter.run("second fixture", [tool])
        assert len(clients) == 2 and clients[0] is not clients[1]
        assert closed == [True, True] and len(second.tool_calls) == 1
        assert second.usage == {
            "prompt_tokens": sum(clients[1].count_tokens(call["messages"]) for call in clients[1].create_calls),
            "completion_tokens": 8,
        }
        assert len(effects) == 2
        assert [message.content for message in clients[1].create_calls[0]["messages"]
                if getattr(message, "source", None) == "user"] == ["second fixture"]


@pytest.mark.skipif(os.environ.get("DSB_FRAMEWORK") != "openai-agents", reason="optional OpenAI SDK matrix")
@pytest.mark.parametrize("mode", ["answer", "empty", "approval", "tool-invalid", "tool-error"])
def test_openai_bridge_runs_native_sdk_loop_without_provider_calls(monkeypatch, native_sync_loop, mode):
    from agents import Model, ModelResponse, RunConfig, Runner, Usage
    from openai.types.responses import (
        ResponseFunctionToolCall,
        ResponseOutputMessage,
        ResponseOutputText,
    )

    from dspy_security_bench.agents import AgentResultError
    from dspy_security_bench.integrations import NativeToolExecutionError
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

    def record():
        effects.append(True)
        if mode == "tool-error":
            raise LookupError("synthetic tool callback failure")
        return None if mode == "tool-invalid" else "recorded"

    tool = BenchTool("record", "Record a fictional action.", {"type": "object", "properties": {}},
                     record)
    if mode in {"tool-invalid", "tool-error"}:
        with pytest.raises(AgentResultError if mode == "tool-invalid" else NativeToolExecutionError):
            adapter.run("fixture", [tool])
        assert effects == [True] and captured[0].final_output == "done" and model.calls == 2
    elif mode == "approval":
        with pytest.raises(AgentResultError, match="awaits approval"):
            adapter.run("fixture", [tool])
        assert effects == [] and model.calls == 1
        assert captured[0].interruptions
    else:
        result = adapter.run("fixture", [tool])
        assert result.final_answer == ("" if mode == "empty" else "done")
        assert result.tool_calls[0].result == "recorded"
        assert effects == [True] and model.calls == 2
        assert result.usage == {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10, "requests": 2}
        assert captured[0].interruptions == []


@pytest.mark.skipif(os.environ.get("DSB_FRAMEWORK") != "langchain", reason="optional LangChain SDK matrix")
@pytest.mark.parametrize("mode", ["answer", "empty", "blocks", "approval", "static-pause",
                                 "missing-usage", "partial-usage", "invalid-usage", "pruned-state", "error-recovered",
                                 "tool-invalid", "tool-error"])
def test_langchain_bridge_runs_native_agent_loop_without_provider_calls(monkeypatch, mode):
    from types import SimpleNamespace

    from langchain.agents import create_agent
    from langchain.agents.middleware import HumanInTheLoopMiddleware, wrap_tool_call
    from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
    from langchain_core.messages import AIMessage, ToolMessage
    from langgraph.checkpoint.memory import InMemorySaver
    from langsmith import tracing_context

    from dspy_security_bench.agents import AgentResultError
    from dspy_security_bench.integrations import LangChainAdapter, NativeToolExecutionError

    def no_network(*args, **kwargs):
        pytest.fail("native compatibility fixture must not contact providers or tracing services")

    monkeypatch.setattr("socket.socket.connect", no_network)
    monkeypatch.setattr("socket.socket.connect_ex", no_network)
    monkeypatch.setattr("socket.getaddrinfo", no_network)

    failures = []

    class CannedModel(FakeMessagesListChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

        def _generate(self, *args, **kwargs):
            if mode == "error-recovered" and not failures:
                failures.append(True)
                raise LookupError("synthetic failed model call")
            return super()._generate(*args, **kwargs)

    content = "" if mode == "empty" else "done"
    if mode == "blocks":
        content = [{"type": "reasoning", "reasoning": "PRIVATE"},
                   {"type": "text", "text": "do"}, {"type": "text", "text": "ne"}]
    responses = [
        AIMessage(content="", tool_calls=[{"name": "record", "args": {}, "id": "fixture-call", "type": "tool_call"}]),
        AIMessage(content=content),
    ]
    # Assign malformed/missing fixtures after construction to avoid SDK coercion.
    first_usage = {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}
    if mode == "missing-usage":
        first_usage = None
    elif mode == "partial-usage":
        first_usage.pop("total_tokens")
    elif mode == "invalid-usage":
        first_usage["input_tokens"] = True
    responses[0].usage_metadata = first_usage
    responses[1].usage_metadata = {"input_tokens": 7, "output_tokens": 11, "total_tokens": 18}
    model = CannedModel(responses=responses)
    captured, effects, callbacks = [], [], []

    @wrap_tool_call
    def recover_tool_failure(request, handler):
        try:
            return handler(request)
        except Exception:
            return ToolMessage(content="Synthetic recovery", tool_call_id=request.tool_call["id"])

    def native_create(**kwargs):
        options = {}
        if mode in {"tool-invalid", "tool-error"}:
            options["middleware"] = [recover_tool_failure]
        elif mode == "approval":
            options["middleware"] = [HumanInTheLoopMiddleware(interrupt_on={"record": True})]
            options["checkpointer"] = InMemorySaver()
        elif mode == "static-pause":
            options["interrupt_before"] = ["tools"]
            options["checkpointer"] = InMemorySaver()
        graph = create_agent(**kwargs, **options)

        def invoke(payload, *, config):
            callbacks.append(config["callbacks"][0])
            config = {**config, "configurable": {"thread_id": "fixture"}}
            with tracing_context(enabled=False):
                try:
                    result = graph.invoke(payload, config=config)
                except LookupError:
                    if mode != "error-recovered":
                        raise
                    result = graph.invoke(payload, config=config)
            if mode == "pruned-state":
                result["messages"] = result["messages"][-1:]
            captured.append(result)
            return result

        return SimpleNamespace(invoke=invoke)

    monkeypatch.setattr("langchain.agents.create_agent", native_create)

    def record():
        effects.append(True)
        if mode == "tool-error":
            raise LookupError("synthetic tool callback failure")
        return None if mode == "tool-invalid" else "recorded"

    tool = BenchTool("record", "Record a fictional action.", {"type": "object", "properties": {}},
                     record)
    adapter = LangChainAdapter(model=model)
    if mode in {"tool-invalid", "tool-error"}:
        with pytest.raises(AgentResultError if mode == "tool-invalid" else NativeToolExecutionError):
            adapter.run("fixture", [tool])
        assert effects == [True] and captured[0]["messages"][-1].content == "done"
    elif mode in {"approval", "static-pause"}:
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
        expected = {"prompt_tokens": 9, "completion_tokens": 14, "total_tokens": 23}
        if mode in {"missing-usage", "error-recovered"}:
            expected = {}
        elif mode == "partial-usage":
            expected.pop("total_tokens")
        elif mode == "invalid-usage":
            expected.pop("prompt_tokens")
        assert result.usage == expected
        if mode == "answer":
            second = adapter.run("second fixture", [tool])
            assert second.usage == expected and effects == [True, True]
            assert callbacks[0] is not callbacks[1]


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
