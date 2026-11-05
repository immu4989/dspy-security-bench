"""Real AgentDojo tools obey a task-scoped cooperative lifetime boundary."""

import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, Thread
from types import SimpleNamespace

import pytest
from agentdojo.functions_runtime import Depends, Function, FunctionsRuntime, TaskEnvironment
from pydantic import BaseModel, Field

from dspy_security_bench.adapters.generic import GenericAgentElement
from dspy_security_bench.agents import AgentResult, AgentResultError, AgentToolExecutionError
from dspy_security_bench.defenses import NoDefense
from dspy_security_bench.integrations import NativeToolExecutionError


class Params(BaseModel):
    count: int = 1


class Environment(TaskEnvironment):
    values: list[int] = Field(default_factory=list)


def fixture(callback=None):
    def action(env, count):
        env.values.append(count)
        return str(count)

    function = Function(name="action", description="Synthetic action", parameters=Params,
                        dependencies={"env": Depends(lambda env: env)}, run=callback or action,
                        full_docstring="Synthetic action", return_type=str)
    return FunctionsRuntime([function]), Environment()


def element(execute, defense=None):
    return GenericAgentElement(SimpleNamespace(name="fixture", run=execute), defense=defense)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("lifecycle tests must not contact any service")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)


def test_retained_tool_handles_close_after_success_without_a_reported_ledger():
    runtime, env = fixture()
    captured = []

    def execute(query, tools, **kwargs):
        captured.extend(tools)
        assert tools[0]() == "1"
        return AgentResult("done")

    pipeline = element(execute)
    for _ in range(2):
        pipeline.query("query", runtime, env)
    assert captured[0] is not captured[1]
    for tool in captured:
        with pytest.raises(AgentToolExecutionError, match="closed"):
            tool()
    assert env.values == [1, 1]


@pytest.mark.parametrize("error", [LookupError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_escaping_agent_errors_keep_identity_and_close_handles(error):
    runtime, env = fixture()
    captured = []
    failure = error("PRIVATE failure")

    def execute(query, tools, **kwargs):
        captured.extend(tools)
        tools[0]()
        raise failure

    with pytest.raises(error) as caught:
        element(execute).query("query", runtime, env)
    assert caught.value is failure
    with pytest.raises(AgentToolExecutionError, match="closed"):
        captured[0]()
    assert env.values == [1]


@pytest.mark.parametrize("value", [None, "not a result", AgentResult(None)])
def test_malformed_agent_result_still_closes_handles(value):
    runtime, env = fixture()
    captured = []

    def execute(query, tools, **kwargs):
        captured.extend(tools)
        tools[0]()
        return value

    with pytest.raises(AgentResultError):
        element(execute).query("query", runtime, env)
    with pytest.raises(AgentToolExecutionError, match="closed"):
        captured[0]()
    assert env.values == [1]


@pytest.mark.parametrize("mode", ["invalid-return", "defense-error", "runtime-error"])
def test_caught_callback_failures_block_following_calls_and_invalidate_task(monkeypatch, mode):
    runtime, env = fixture()
    original = runtime.run_function
    errors = []

    class BrokenDefense(NoDefense):
        def wrap_tool_output(self, value, **kwargs):
            if mode == "invalid-return":
                return None
            if mode == "defense-error":
                raise LookupError("PRIVATE defense error")
            return value

    def broken_runtime(*args, **kwargs):
        original(*args, **kwargs)
        raise LookupError("PRIVATE runtime error")

    if mode == "runtime-error":
        monkeypatch.setattr(runtime, "run_function", broken_runtime)

    def execute(query, tools, **kwargs):
        for _ in range(2):
            try:
                tools[0]()
            except Exception as exc:
                errors.append(type(exc))
        return AgentResult("recovered")  # No self-reported trace to reveal failure.

    expected = AgentResultError if mode == "invalid-return" else AgentToolExecutionError
    with pytest.raises(expected) as caught:
        element(execute, BrokenDefense()).query("query", runtime, env)
    assert "PRIVATE" not in str(caught.value)
    assert errors == [AgentResultError if mode == "invalid-return" else LookupError, AgentToolExecutionError]
    assert env.values == [1]  # Preserve the first effect, deny the subsequent one.


@pytest.mark.parametrize("error", [LookupError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_escaping_callback_errors_keep_identity_and_close_handles(error):
    runtime, env = fixture()
    captured = []
    failure = error("PRIVATE callback failure")

    class BrokenDefense(NoDefense):
        def wrap_tool_output(self, value, **kwargs):
            raise failure

    def execute(query, tools, **kwargs):
        captured.extend(tools)
        tools[0]()
        return AgentResult("unreachable")

    with pytest.raises(error) as caught:
        element(execute, BrokenDefense()).query("query", runtime, env)
    assert caught.value is failure
    with pytest.raises(AgentToolExecutionError, match="closed"):
        captured[0]()
    assert env.values == [1]


@pytest.mark.parametrize("failure", ["arguments", "domain"])
def test_runtime_error_text_remains_recoverable(failure):
    def action(env, count):
        if count == 0:
            raise ValueError("synthetic domain rejection")
        env.values.append(count)
        return str(count)

    runtime, env = fixture(action)

    def execute(query, tools, **kwargs):
        rejected = tools[0](count="invalid" if failure == "arguments" else 0)
        assert ("ValidationError" if failure == "arguments" else "ValueError") in rejected
        assert tools[0](count=2) == "2"
        return AgentResult("recovered")

    element(execute).query("query", runtime, env)
    assert env.values == [2]


@pytest.mark.parametrize("text", ["", "ok", "[error] synthetic domain rejection"])
def test_explicit_defended_text_is_not_inferred_failure(text):
    runtime, env = fixture()

    class TextDefense(NoDefense):
        def wrap_tool_output(self, value, **kwargs):
            return text

    def execute(query, tools, **kwargs):
        assert tools[0]() == text
        return AgentResult("done")

    element(execute, TextDefense()).query("query", runtime, env)
    assert env.values == [1]


def test_failure_does_not_poison_a_later_task_on_same_element():
    runtime, env = fixture()

    class OnceBroken(NoDefense):
        def wrap_tool_output(self, value, **kwargs):
            if value == "1":
                raise LookupError("synthetic error")
            return value

    def execute(query, tools, **kwargs):
        try:
            tools[0](count=int(query))
        except LookupError:
            pass
        return AgentResult("done")

    pipeline = element(execute, OnceBroken())
    with pytest.raises(AgentToolExecutionError):
        pipeline.query("1", runtime, env)
    pipeline.query("2", runtime, env)
    assert env.values == [1, 2]


@pytest.mark.parametrize("already_started", [False, True], ids=["late-call", "active-call"])
def test_background_callbacks_cannot_create_completed_measurements(already_started):
    started, release = Event(), Event()
    workers, errors, captured = [], [], []

    def action(env, count):
        started.set()
        assert release.wait(10)
        env.values.append(count)
        return str(count)

    runtime, env = fixture(action)

    def execute(query, tools, **kwargs):
        captured.extend(tools)

        def background():
            try:
                if not already_started:
                    assert release.wait(10)
                tools[0]()
            except BaseException as exc:
                errors.append(exc)

        worker = Thread(target=background)
        workers.append(worker)
        worker.start()
        if already_started:
            assert started.wait(10)
        return AgentResult("returned early")

    try:
        if already_started:
            with pytest.raises(AgentToolExecutionError, match="unfinished"):
                element(execute).query("query", runtime, env)
        else:
            element(execute).query("query", runtime, env)
        assert env.values == []
        with pytest.raises(AgentToolExecutionError, match="closed"):
            captured[0]()
    finally:
        release.set()
        for worker in workers:
            worker.join(10)
            assert not worker.is_alive()
    if already_started:
        assert env.values == [1] and not errors  # No rollback/cancellation claim.
    else:
        assert env.values == [] and len(errors) == 1
        assert isinstance(errors[0], AgentToolExecutionError)


def test_concurrent_queries_have_independent_failure_latches():
    runtime, env = fixture()
    ready = Barrier(2)

    class SelectiveDefense(NoDefense):
        def wrap_tool_output(self, value, **kwargs):
            if value == "1":
                raise LookupError("synthetic first-task failure")
            return value

    def execute(query, tools, **kwargs):
        ready.wait(10)
        try:
            tools[0](count=int(query))
        except LookupError:
            pass
        return AgentResult("done")

    pipeline = element(execute, SelectiveDefense())
    with ThreadPoolExecutor(max_workers=2) as executor:
        failed = executor.submit(pipeline.query, "1", runtime, env)
        completed = executor.submit(pipeline.query, "2", runtime, env)
        with pytest.raises(AgentToolExecutionError):
            failed.result(timeout=10)
        assert completed.result(timeout=10)[3][-1]["role"] == "assistant"
    assert sorted(env.values) == [1, 2]


def test_session_closes_before_validating_the_agents_returned_ledger():
    started, release = Event(), Event()
    workers = []

    def action(env, count):
        started.set()
        assert release.wait(10)
        env.values.append(count)
        return str(count)

    runtime, env = fixture(action)

    class FinishingTrace(list):
        def __iter__(self):
            release.set()
            workers[0].join(10)
            assert not workers[0].is_alive()
            return super().__iter__()

    def execute(query, tools, **kwargs):
        worker = Thread(target=tools[0])
        workers.append(worker)
        worker.start()
        assert started.wait(10)
        return AgentResult("returned early", tool_calls=FinishingTrace())

    try:
        # The active callback finishes during result validation, but this cannot
        # erase its unfinished state at the earlier agent-return boundary.
        with pytest.raises(AgentToolExecutionError, match="unfinished"):
            element(execute).query("query", runtime, env)
    finally:
        release.set()
        for worker in workers:
            worker.join(10)
            assert not worker.is_alive()
    assert env.values == [1]


def test_native_error_is_a_specific_shared_execution_error():
    assert issubclass(NativeToolExecutionError, AgentToolExecutionError)
    assert issubclass(AgentToolExecutionError, RuntimeError)
