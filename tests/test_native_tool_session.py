"""Native SDK error recovery must not conceal invalid supplied-tool execution."""

import asyncio
import inspect
import json
import sys
from threading import Event, Thread
from types import ModuleType, SimpleNamespace

import pytest

from dspy_security_bench.agents import AgentResultError, BenchTool
from dspy_security_bench.integrations import (
    AutoGenAdapter,
    CrewAIAdapter,
    LangChainAdapter,
    NativeToolExecutionError,
    OpenAIAgentsAdapter,
    PydanticAIAdapter,
)
from dspy_security_bench.integrations.frameworks import _run_awaitable, _tool_callable
from dspy_security_bench.integrations.tools import _ToolSession


@pytest.mark.parametrize("value", [None, False, 0, {}, []], ids=["none", "bool", "number", "object", "array"])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_native_tool_results_are_not_implicitly_stringified(value, asynchronous):
    effects, ledger = [], []
    function = _tool_callable(BenchTool("act", "Synthetic action", {}, lambda: effects.append(True) or value),
                              ledger, asynchronous=asynchronous)
    with pytest.raises(AgentResultError):
        result = function()
        if asynchronous:
            asyncio.run(result)
    assert effects == [True] and ledger == []


def call(function):
    value = function()
    return _run_awaitable(value) if inspect.isawaitable(value) else value


@pytest.fixture(params=["openai", "langchain", "pydantic", "crewai", "autogen"])
def framework(request):
    return request.param


def bridge(monkeypatch, framework, execute):
    captured, closed, reads = [], [], []

    def result():
        if framework == "langchain":
            return {"messages": [SimpleNamespace(type="ai", content="done", tool_calls=[], invalid_tool_calls=[])]}
        return SimpleNamespace(final_output="done", interruptions=[], output="done", raw="done", agent_role="crewai-agent",
                               stop_reason=None, messages=[SimpleNamespace(type="TextMessage", source="autogen_agent", content="done")])

    class Agent:
        def __init__(self, *args, tools, **kwargs):
            self.tools = tools
            captured.extend(tools)

        def run_sync(self, query):
            execute(self.tools[0])
            return result()

        kickoff = run_sync

        def invoke(self, payload, *, config):
            return self.run_sync(payload)

        async def run(self, *, task):
            return self.run_sync(task)

    class Client:
        def __init__(self, **kwargs):
            pass

        async def close(self):
            closed.append(True)

    class Usage:
        def usage(self):
            reads.append(True)
            return {}

    def install(name, **values):
        module = ModuleType(name)
        module.__dict__.update(values)
        monkeypatch.setitem(sys.modules, name, module)

    if framework == "openai":
        install("agents", Agent=Agent, function_tool=lambda function: function,
                Runner=SimpleNamespace(run_sync=lambda agent, query: agent.run_sync(query)))
    elif framework == "langchain":
        install("langchain")
        install("langchain.agents", create_agent=Agent)
        monkeypatch.setattr("dspy_security_bench.integrations.frameworks._langchain_usage_callback", Usage)
    elif framework == "pydantic":
        install("pydantic_ai", Agent=Agent)
    elif framework == "crewai":
        install("crewai", Agent=Agent)
        install("crewai.tools", tool=lambda name: lambda function: function)
    else:
        install("autogen_agentchat")
        install("autogen_agentchat.agents", AssistantAgent=Agent)
        install("autogen_ext")
        install("autogen_ext.models")
        install("autogen_ext.models.openai", OpenAIChatCompletionClient=Client)
    adapter = {"openai": OpenAIAgentsAdapter, "langchain": LangChainAdapter, "pydantic": PydanticAIAdapter,
               "crewai": CrewAIAdapter, "autogen": AutoGenAdapter}[framework](model="fixture")
    return adapter, captured, closed, reads


@pytest.mark.parametrize("failure", ["invalid-result", "exception"])
def test_swallowed_tool_failure_cannot_become_scored_native_result(monkeypatch, framework, failure):
    effects, caught = [], []

    def execute(function):
        for _ in range(2):
            try:
                call(function)
            except Exception as exc:
                caught.append(type(exc))

    adapter, captured, closed, reads = bridge(monkeypatch, framework, execute)

    def action():
        effects.append(True)
        if failure == "exception":
            raise LookupError("PRIVATE tool error")
        return None

    expected = AgentResultError if failure == "invalid-result" else NativeToolExecutionError
    with pytest.raises(expected) as error:
        adapter.run("query", [BenchTool("act", "Synthetic action", {}, action)])
    assert "PRIVATE" not in str(error.value)
    assert effects == [True] and len(caught) == 2
    assert caught[-1] is NativeToolExecutionError
    assert closed == ([True] if framework == "autogen" else [])
    assert not reads
    with pytest.raises(NativeToolExecutionError, match="closed"):
        call(captured[0])
    assert effects == [True]


@pytest.mark.parametrize("answer", ["", "recorded", "[error] action denied by domain policy"])
def test_explicit_text_and_domain_errors_are_not_inferred_failures(monkeypatch, framework, answer):
    adapter, captured, _, _ = bridge(monkeypatch, framework, lambda function: call(function))
    effects = []
    tool = BenchTool("act", "Synthetic action", {}, lambda: effects.append(True) or answer)
    for _ in range(2):
        result = adapter.run("query", [tool])
        assert result.final_answer == "done" and len(result.tool_calls) == 1
        assert result.tool_calls[0].result == answer
    assert effects == [True, True] and captured[0] is not captured[1]
    for function in captured:
        with pytest.raises(NativeToolExecutionError, match="closed"):
            call(function)
    assert effects == [True, True]


@pytest.mark.parametrize("error", [LookupError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_escaping_exceptions_keep_their_type_and_close_tool_handles(monkeypatch, framework, error):
    failure = error("PRIVATE failure")

    def execute(function):
        call(function)
        raise failure

    adapter, captured, closed, _ = bridge(monkeypatch, framework, execute)
    effects = []
    with pytest.raises(error):
        adapter.run("query", [BenchTool("act", "Synthetic action", {}, lambda: effects.append(True) or "done")])
    with pytest.raises(NativeToolExecutionError, match="closed"):
        call(captured[0])
    assert effects == [True] and closed == ([True] if framework == "autogen" else [])


def test_failed_invocation_does_not_poison_next_native_run(monkeypatch, framework):
    def execute(function):
        try:
            call(function)
        except AgentResultError:
            pass

    adapter, captured, _, _ = bridge(monkeypatch, framework, execute)
    with pytest.raises(AgentResultError):
        adapter.run("first", [BenchTool("act", "", {}, lambda: None)])
    result = adapter.run("second", [BenchTool("act", "", {}, lambda: "done")])
    assert result.final_answer == "done" and len(result.tool_calls) == 1
    assert captured[0] is not captured[1]


def test_adapter_rejects_sdk_return_while_supplied_callback_is_in_flight(monkeypatch, framework):
    started, release = Event(), Event()
    workers, effects, errors = [], [], []

    def execute(function):
        def background():
            try:
                call(function)
            except BaseException as exc:
                errors.append(exc)

        worker = Thread(target=background)
        workers.append(worker)
        worker.start()
        assert started.wait(2)

    def action():
        effects.append(True)
        started.set()
        assert release.wait(5)
        return "done"

    adapter, captured, _, _ = bridge(monkeypatch, framework, execute)
    try:
        with pytest.raises(NativeToolExecutionError, match="unfinished"):
            adapter.run("query", [BenchTool("act", "", {}, action)])
        with pytest.raises(NativeToolExecutionError, match="closed"):
            call(captured[0])
    finally:
        release.set()
        for worker in workers:
            worker.join(2)
            assert not worker.is_alive()
    assert effects == [True] and errors == []


def test_prior_tool_records_survive_failure_without_fabricating_failed_result():
    effects, ledger = [], []
    with _ToolSession() as session:
        good = _tool_callable(BenchTool("good", "", {}, lambda: effects.append("good") or ""), ledger, session=session)
        bad = _tool_callable(BenchTool("bad", "", {}, lambda: effects.append("bad")), ledger, session=session)
        assert good() == ""
        with pytest.raises(AgentResultError):
            bad()
    with pytest.raises(AgentResultError):
        session.validate()
    assert effects == ["good", "bad"] and [item.name for item in ledger] == ["good"]


def test_unfinished_callback_cannot_become_complete_by_finishing_after_close():
    started, release = Event(), Event()
    ledger, effects = [], []

    def action():
        effects.append(True)
        started.set()
        assert release.wait(5)
        return "done"

    with _ToolSession() as session:
        function = _tool_callable(BenchTool("act", "", {}, action), ledger, session=session)
        worker = Thread(target=function)
        worker.start()
        assert started.wait(2)
    try:
        with pytest.raises(NativeToolExecutionError, match="unfinished"):
            session.validate()
        with pytest.raises(NativeToolExecutionError, match="closed"):
            function()
    finally:
        release.set()
        worker.join(2)
        assert not worker.is_alive()
    with pytest.raises(NativeToolExecutionError, match="unfinished"):
        session.validate()
    assert effects == [True] and len(ledger) == 1


def test_already_admitted_parallel_callback_is_not_rolled_back_or_cancelled():
    started, release = Event(), Event()
    ledger, effects = [], []

    def in_flight():
        started.set()
        assert release.wait(5)
        effects.append("finished")
        return "done"

    with _ToolSession() as session:
        pending = _tool_callable(BenchTool("pending", "", {}, in_flight), ledger, session=session)
        invalid = _tool_callable(BenchTool("bad", "", {}, lambda: None), ledger, session=session)
        worker = Thread(target=pending)
        worker.start()
        assert started.wait(2)
        try:
            with pytest.raises(AgentResultError):
                invalid()
            with pytest.raises(NativeToolExecutionError, match="failed"):
                pending()
        finally:
            release.set()
            worker.join(2)
            assert not worker.is_alive()
    with pytest.raises(AgentResultError):
        session.validate()
    assert effects == ["finished"] and [item.name for item in ledger] == ["pending"]


def test_private_objects_are_not_coerced_or_retained_in_error_text():
    class Private:
        def __str__(self):
            pytest.fail("must not stringify a private tool result")

        def __repr__(self):
            pytest.fail("must not represent a private tool result")

    with _ToolSession() as session:
        function = _tool_callable(BenchTool("act", "", {}, Private), [], session=session)
        with pytest.raises(AgentResultError):
            function()
    with pytest.raises(AgentResultError) as error:
        session.validate()
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("invalid_result", [False, True])
def test_native_tool_failures_remain_mission_errors_without_erasing_harms(monkeypatch, framework, invalid_result):
    from dspy_security_bench.procurement.repeat import run_repeat_twin, validate_repeat_payload

    def recover(function):
        try:
            call(function)
        except Exception:
            pass

    adapter, _, _, _ = bridge(monkeypatch, framework, recover)

    class FaultyToolFixture:
        name = "synthetic-native-tool-failure"

        def run(self, query, tools, *, system_directive=""):
            supplied = next(tool for tool in tools if tool.name == "release_source_selection")

            def action():
                supplied(recipient="synthetic-recipient@example.test", proposal_ids=["P-ATLAS"])
                if not invalid_result:
                    raise LookupError("PRIVATE callback failure")
                return None

            return adapter.run(query, [BenchTool("act", "Synthetic action", {}, action)], system_directive=system_directive)

    payload = run_repeat_twin(FaultyToolFixture(), trials=2).to_dict()
    assert payload["summary"]["case_errors"] == 20
    for trial in payload["trials"]:
        for pair in trial["pairs"]:
            for case in (pair["clean"], pair["injected"]):
                assert case["error"] == ("invalid_agent_result" if invalid_result else "agent_execution_error")
                assert not case["mission_completed"] and case["prohibited_side_effects"] and case["action_trace"]
    assert "PRIVATE" not in json.dumps(payload)
    assert validate_repeat_payload(payload) == ()
