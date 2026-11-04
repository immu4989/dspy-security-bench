"""Offline callback interoperability without providers, SDKs, or nested loops."""

from __future__ import annotations

import asyncio
import threading
from contextvars import ContextVar

import pytest

from dspy_security_bench.agents import AgentResult, AgentResultError, BenchTool, ToolCall
from dspy_security_bench.integrations import CallbackAdapter

REQUEST_CONTEXT = ContextVar("callback_test_request", default="missing")


class AwaitableValue:
    """A general awaitable, not a coroutine or Future."""

    def __init__(self, factory):
        self.factory = factory

    def __await__(self):
        return self.factory().__await__()


def invoke(adapter, api):
    if api == "run":
        return adapter.run("query", [], system_directive="trusted")
    return asyncio.run(adapter.arun("query", [], system_directive="trusted"))


@pytest.mark.parametrize("inside_loop", [False, True])
@pytest.mark.parametrize("general_awaitable", [False, True])
def test_sync_bridge_preserves_context_and_live_tools(inside_loop, general_awaitable):
    caller_thread = threading.get_ident()
    calls = []
    tool = BenchTool(
        name="lookup", description="Synthetic lookup", parameters={},
        _call=lambda: calls.append(REQUEST_CONTEXT.get()) or "record",
    )

    def runner(query, tools, directive):
        assert (query, tools, directive) == ("query", [tool], "trusted")
        assert threading.get_ident() == caller_thread

        async def execute():
            assert REQUEST_CONTEXT.get() == "request-A"
            assert (threading.get_ident() != caller_thread) is inside_loop
            await asyncio.sleep(0)
            result = tools[0]()
            REQUEST_CONTEXT.set("worker-change")
            return AgentResult("done", [ToolCall("lookup", {}, result)])

        return AwaitableValue(execute) if general_awaitable else execute()

    def check():
        token = REQUEST_CONTEXT.set("request-A")
        try:
            result = CallbackAdapter(runner).run("query", [tool], system_directive="trusted")
            assert REQUEST_CONTEXT.get() == "request-A"
            assert result.final_answer == "done"
            assert result.tool_calls == [ToolCall("lookup", {}, "record")]
        finally:
            REQUEST_CONTEXT.reset(token)

    async def nested():
        check()

    asyncio.run(nested()) if inside_loop else check()
    assert calls == ["request-A"]


@pytest.mark.parametrize("api", ["run", "arun"])
@pytest.mark.parametrize("deferred", [False, True])
@pytest.mark.parametrize("value", ["", "answer", AgentResult("answer")])
def test_both_entry_points_admit_same_explicit_results(api, deferred, value):
    async def execute():
        return value

    result = invoke(CallbackAdapter(lambda *args: execute() if deferred else value), api)
    assert result.final_answer == (value.final_answer if isinstance(value, AgentResult) else value)
    if isinstance(value, AgentResult):
        assert result is value


@pytest.mark.parametrize("api", ["run", "arun"])
@pytest.mark.parametrize("deferred", [False, True])
@pytest.mark.parametrize("value", [None, 3, {}, AgentResult(None), AgentResult("ok", [None])])
def test_both_entry_points_reject_malformed_results(api, deferred, value):
    async def execute():
        return value

    with pytest.raises(AgentResultError):
        invoke(CallbackAdapter(lambda *args: execute() if deferred else value), api)


@pytest.mark.parametrize("kind", ["coroutine", "awaitable", "future", "task"])
def test_arun_awaits_in_callers_loop_and_context(kind):
    async def scenario():
        loop = asyncio.get_running_loop()
        caller_thread = threading.get_ident()
        seen = []

        async def execute():
            assert asyncio.get_running_loop() is loop
            assert threading.get_ident() == caller_thread
            seen.append(REQUEST_CONTEXT.get())
            await asyncio.sleep(0)
            return "answer"

        def runner(query, tools, directive):
            assert (query, tools, directive) == ("query", [], "trusted")
            if kind == "future":
                future = loop.create_future()
                loop.call_soon(lambda: seen.append(REQUEST_CONTEXT.get()))
                loop.call_soon(future.set_result, "answer")
                return future
            if kind == "task":
                return asyncio.create_task(execute())
            return AwaitableValue(execute) if kind == "awaitable" else execute()

        token = REQUEST_CONTEXT.set("request-B")
        try:
            result = await CallbackAdapter(runner).arun("query", [], system_directive="trusted")
            assert result.final_answer == "answer"
            assert seen == ["request-B"]
        finally:
            REQUEST_CONTEXT.reset(token)

    asyncio.run(scenario())


@pytest.mark.parametrize("inside_loop", [False, True])
@pytest.mark.parametrize("kind", ["future", "task"])
def test_sync_bridge_refuses_pending_owned_work_without_driving_or_cancelling(inside_loop, kind):
    effects = []

    async def execute():
        effects.append("executed")
        return "answer"

    def check(loop):
        value = loop.create_task(execute()) if kind == "task" else loop.create_future()
        try:
            with pytest.raises(RuntimeError, match=r"pending.*arun"):
                CallbackAdapter(lambda *args: value).run("query", [])
            assert not value.done()
            assert not value.cancelled()
            assert not effects
        finally:
            value.cancel()  # The owner, not the adapter, cleans up its work.
        return value

    async def nested():
        value = check(asyncio.get_running_loop())
        await asyncio.gather(value, return_exceptions=True)

    async def finish(value):
        await asyncio.gather(value, return_exceptions=True)

    if inside_loop:
        asyncio.run(nested())
    else:
        loop = asyncio.new_event_loop()
        try:
            value = check(loop)
            loop.run_until_complete(finish(value))
        finally:
            loop.close()
    assert not effects


@pytest.mark.parametrize("api", ["run", "arun"])
@pytest.mark.parametrize("terminal", ["result", "exception", "cancelled"])
def test_completed_future_from_closed_loop_keeps_terminal_outcome(api, terminal):
    loop = asyncio.new_event_loop()
    value = loop.create_future()
    error = LookupError("synthetic failure")
    if terminal == "result":
        value.set_result("answer")
    elif terminal == "exception":
        value.set_exception(error)
    else:
        value.cancel()
    loop.close()
    adapter = CallbackAdapter(lambda *args: value)
    if terminal == "result":
        assert invoke(adapter, api).final_answer == "answer"
    else:
        expected = LookupError if terminal == "exception" else asyncio.CancelledError
        with pytest.raises(expected) as captured:
            invoke(adapter, api)
        if terminal == "exception":
            assert captured.value is error


@pytest.mark.parametrize("api", ["run", "arun"])
@pytest.mark.parametrize("deferred", [False, True])
def test_callback_exceptions_are_not_converted_into_answers(api, deferred):
    error = LookupError("synthetic callback failure")

    async def execute():
        raise error

    def runner(*args):
        if deferred:
            return execute()
        raise error

    with pytest.raises(LookupError) as captured:
        invoke(CallbackAdapter(runner), api)
    assert captured.value is error


def test_arun_cancellation_reaches_callback_cleanup():
    async def scenario():
        started = asyncio.Event()
        cleaned = []

        async def runner(*args):
            try:
                started.set()
                await asyncio.Future()
            finally:
                cleaned.append(True)

        task = asyncio.create_task(CallbackAdapter(runner).arun("query", []))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cleaned == [True]

    asyncio.run(scenario())


def test_concurrent_arun_calls_keep_separate_request_contexts():
    async def scenario():
        ready = asyncio.Event()
        seen = []

        async def runner(query, tools, directive):
            seen.append(REQUEST_CONTEXT.get())
            if len(seen) == 2:
                ready.set()
            await ready.wait()
            return REQUEST_CONTEXT.get()

        adapter = CallbackAdapter(runner)

        async def request(name):
            token = REQUEST_CONTEXT.set(name)
            try:
                return (await adapter.arun("query", [])).final_answer
            finally:
                REQUEST_CONTEXT.reset(token)

        assert await asyncio.gather(request("request-A"), request("request-B")) == [
            "request-A", "request-B",
        ]
        assert sorted(seen) == ["request-A", "request-B"]
        assert REQUEST_CONTEXT.get() == "missing"

    asyncio.run(scenario())


def test_arun_does_not_transfer_or_cancel_a_foreign_pending_future():
    owner = asyncio.new_event_loop()
    value = owner.create_future()
    try:
        with pytest.raises(RuntimeError, match="different loop"):
            invoke(CallbackAdapter(lambda *args: value), "arun")
        assert not value.done()
        assert value.get_loop() is owner
    finally:
        value.cancel()
        owner.close()


@pytest.mark.parametrize("api", ["run", "arun"])
def test_awaited_objects_are_never_stringified(api):
    class PrivateValue:
        def __str__(self):
            pytest.fail("must not stringify callback result")

        def __repr__(self):
            pytest.fail("must not represent callback result")

    async def runner(*args):
        return PrivateValue()

    with pytest.raises(AgentResultError, match="custom callback must return text or an AgentResult"):
        invoke(CallbackAdapter(runner), api)
