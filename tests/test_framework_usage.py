"""Optional SDK telemetry must not invent evidence or invalidate completed work."""

import asyncio
import json
import sys
from decimal import Decimal
from types import ModuleType, SimpleNamespace

import pytest

from dspy_security_bench.agents import AgentResultError, BenchTool, normalize_usage
from dspy_security_bench.integrations import (
    AutoGenAdapter,
    CrewAIAdapter,
    OpenAIAgentsAdapter,
    PydanticAIAdapter,
)
from dspy_security_bench.integrations.frameworks import _usage


class PrivateValue:
    def __str__(self):
        pytest.fail("usage must not be coerced to text")

    def __repr__(self):
        pytest.fail("usage must not be represented")


class UnreadableUsage:
    def __getattr__(self, name):
        raise ValueError("PRIVATE telemetry failure")


def failed_usage():
    raise LookupError("PRIVATE telemetry accessor failure")


@pytest.mark.parametrize("as_object", [False, True])
def test_missing_totals_are_not_invented(as_object):
    raw = {"input_tokens": 2, "output_tokens": 3}
    result = _usage(SimpleNamespace(**raw) if as_object else raw)
    assert result == {"prompt_tokens": 2, "completion_tokens": 3}
    assert normalize_usage(result) == result


@pytest.mark.parametrize("field", ["prompt_tokens", "completion_tokens", "total_tokens", "requests"])
@pytest.mark.parametrize("value", [None, True, False, -1, 2.0, 1.5, "2", float("inf"), float("nan"), PrivateValue()],
                         ids=["none", "true", "false", "negative", "integral-float", "fraction", "text", "inf", "nan", "private"])
def test_counts_require_nonnegative_integers(field, value):
    assert _usage({field: value, "estimated_cost_usd": 0.25}) == {"estimated_cost_usd": 0.25}


@pytest.mark.parametrize("value", [True, -1, float("inf"), float("nan"), 10**1000, "0.1", Decimal("0.1"), PrivateValue()],
                         ids=["bool", "negative", "inf", "nan", "overflow", "text", "decimal", "private"])
def test_invalid_cost_is_unknown_while_valid_counts_survive(value):
    result = _usage({"estimated_cost_usd": value, "total_tokens": 0})
    assert result == {"total_tokens": 0}
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize("raw", [None, [], "PRIVATE", PrivateValue(), UnreadableUsage(), failed_usage],
                         ids=["none", "array", "text", "private", "attributes-fail", "call-fails"])
def test_unavailable_optional_usage_is_empty(raw):
    assert _usage(raw) == {}


@pytest.mark.parametrize("aliases,target", [
    (("prompt_tokens", "input_tokens", "request_tokens"), "prompt_tokens"),
    (("completion_tokens", "output_tokens", "response_tokens"), "completion_tokens"),
])
@pytest.mark.parametrize("as_object", [False, True])
@pytest.mark.parametrize("mode", ["one", "agree", "conflict", "invalid", "null"])
def test_aliases_must_agree_without_silent_precedence(aliases, target, as_object, mode):
    raw = {aliases[0]: 3, "requests": 1}
    if mode != "one":
        raw[aliases[1]] = {"agree": 3, "conflict": 4, "invalid": True, "null": None}[mode]
        raw[aliases[2]] = 3
    expected = {"requests": 1}
    if mode in {"one", "agree", "null"}:
        expected[target] = 3
    assert _usage(SimpleNamespace(**raw) if as_object else raw) == expected


def test_valid_fields_are_read_once_and_unreadable_alias_drops_only_its_quantity():
    accesses = []

    class Usage:
        def __getattr__(self, name):
            accesses.append(name)
            if name == "input_tokens":
                raise RuntimeError("PRIVATE input metadata")
            return {"prompt_tokens": 4, "output_tokens": 3, "total_tokens": 7, "requests": 0,
                    "estimated_cost_usd": 1}.get(name)

    result = _usage(Usage())
    assert result == {"completion_tokens": 3, "total_tokens": 7, "requests": 0, "estimated_cost_usd": 1.0}
    assert len(accesses) == len(set(accesses))
    assert "PRIVATE" not in json.dumps(result, allow_nan=False)


def test_usage_method_is_called_once_and_unrelated_payload_is_not_inspected():
    calls = []

    def usage():
        calls.append(True)
        return {"input_tokens": 0, "output_tokens": 3, "total_tokens": 99, "requests": 1,
                "estimated_cost_usd": 0, "details": PrivateValue()}

    result = _usage(usage)
    assert calls == [True]
    # This is field admission, not billing reconciliation or arithmetic repair.
    assert result == {"prompt_tokens": 0, "completion_tokens": 3, "total_tokens": 99,
                      "requests": 1, "estimated_cost_usd": 0.0}


@pytest.mark.parametrize("stage", ["outer", "inner"])
@pytest.mark.parametrize("error", [AttributeError, RuntimeError])
def test_nested_optional_metadata_paths_do_not_become_task_failures(stage, error):
    class Broken:
        def __getattr__(self, name):
            raise error("PRIVATE optional metadata")

    source = Broken() if stage == "outer" else SimpleNamespace(context_wrapper=Broken())
    assert _usage(source, "context_wrapper", "usage") == {}


def test_broken_mapping_access_drops_only_the_affected_quantity():
    class Mapping(dict):
        def get(self, key, *args):
            if key == "prompt_tokens":
                raise ValueError("PRIVATE mapping error")
            return super().get(key, *args)

    assert _usage(Mapping(input_tokens=2, output_tokens=3)) == {"completion_tokens": 3}


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
@pytest.mark.parametrize("stage", ["method", "field", "path"])
def test_control_flow_exceptions_are_not_swallowed(error, stage):
    def stop():
        raise error()

    class Usage:
        @property
        def total_tokens(self):
            stop()

    with pytest.raises(error):
        if stage == "path":
            _usage(Usage(), "total_tokens")
        else:
            _usage(stop if stage == "method" else Usage())


def run_bridge(monkeypatch, framework, usage, *, broken_path=False, invalid_answer=False):
    effects, closed = [], []
    native = SimpleNamespace(
        final_output=None if invalid_answer else "answer", interruptions=[],
        output=None if invalid_answer else "answer", raw=None if invalid_answer else "answer",
        agent_role="crewai-agent", stop_reason=None,
        messages=[SimpleNamespace(type="TextMessage", source="autogen_agent", content=None if invalid_answer else "answer")],
    )
    usage_name = {"openai": "context_wrapper", "pydantic": "usage", "crewai": "usage_metrics", "autogen": "usage"}[framework]

    class Result:
        def __getattr__(self, name):
            if name == usage_name:
                if broken_path:
                    raise RuntimeError("PRIVATE native metadata field")
                return SimpleNamespace(usage=usage) if framework == "openai" else usage
            return getattr(native, name)

    class Agent:
        def __init__(self, *args, tools, **kwargs):
            self.tools = tools

        def run_sync(self, query):
            self.tools[0]()
            return Result()

        kickoff = run_sync

        async def run(self, *, task):
            await self.tools[0]()
            return Result()

    class Client:
        def __init__(self, **kwargs):
            pass

        async def close(self):
            closed.append(True)

    def install(name, **attributes):
        module = ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)

    if framework == "openai":
        install("agents", Agent=Agent, function_tool=lambda f: f,
                Runner=SimpleNamespace(run_sync=lambda agent, query: agent.run_sync(query)))
    elif framework == "pydantic":
        install("pydantic_ai", Agent=Agent)
    elif framework == "crewai":
        install("crewai", Agent=Agent)
        install("crewai.tools", tool=lambda name: lambda f: f)
    else:
        install("autogen_agentchat")
        install("autogen_agentchat.agents", AssistantAgent=Agent)
        install("autogen_ext")
        install("autogen_ext.models")
        install("autogen_ext.models.openai", OpenAIChatCompletionClient=Client)
    adapter = {"openai": OpenAIAgentsAdapter, "pydantic": PydanticAIAdapter,
               "crewai": CrewAIAdapter, "autogen": AutoGenAdapter}[framework](model="fixture")
    tool = BenchTool("record", "Synthetic action", {}, lambda: effects.append(True) or "recorded")
    try:
        return adapter.run("PRIVATE query", [tool])
    finally:
        assert effects == [True]
        assert closed == ([True] if framework == "autogen" else [])


@pytest.mark.parametrize("framework", ["openai", "pydantic", "crewai", "autogen"])
@pytest.mark.parametrize("mode", ["missing", "partial", "invalid", "conflict", "method-fails", "fields-fail", "path-fails"])
def test_completed_bridges_keep_trace_when_optional_telemetry_is_bad(monkeypatch, framework, mode):
    usage = {"missing": None, "partial": {"input_tokens": 2, "output_tokens": 3},
             "invalid": {"total_tokens": 1.5, "estimated_cost_usd": float("inf")},
             "conflict": {"input_tokens": 2, "prompt_tokens": 3},
             "method-fails": failed_usage, "fields-fail": UnreadableUsage(), "path-fails": None}[mode]
    result = run_bridge(monkeypatch, framework, usage, broken_path=mode == "path-fails")
    assert result.final_answer == "answer" and result.tool_calls[0].result == "recorded"
    assert result.usage == ({"prompt_tokens": 2, "completion_tokens": 3} if mode == "partial" else {})
    assert "PRIVATE" not in json.dumps(result.usage, allow_nan=False)


@pytest.mark.parametrize("framework", ["openai", "pydantic", "crewai", "autogen"])
def test_required_admission_still_precedes_optional_telemetry(monkeypatch, framework):
    def usage():
        pytest.fail("invalid answers must be rejected before optional usage is read")

    with pytest.raises(AgentResultError):
        run_bridge(monkeypatch, framework, usage, invalid_answer=True)
