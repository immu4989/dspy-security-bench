"""SDK-free completeness and lifecycle checks for native callback accounting."""

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from types import ModuleType, SimpleNamespace
from uuid import uuid4

import pytest

from dspy_security_bench.agents import AgentResultError, BenchTool
from dspy_security_bench.integrations import LangChainAdapter
from dspy_security_bench.integrations.usage import _langchain_receipt, _LangChainUsageLedger


class PrivateValue:
    def __str__(self):
        pytest.fail("private callback payload must not be stringified")

    def __repr__(self):
        pytest.fail("private callback payload must not be represented")


def response(usage=None, **message_fields):
    message = SimpleNamespace(type="ai", content=PrivateValue(), usage_metadata=usage, **message_fields)
    return SimpleNamespace(generations=[[SimpleNamespace(message=message)]], llm_output=PrivateValue())


def receipt(input_tokens=2, output_tokens=3, total_tokens=5):
    return {"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": total_tokens}


def start(ledger, run_id):
    ledger.on_chat_model_start(PrivateValue(), PrivateValue(), run_id=run_id, metadata=PrivateValue())


def finish(ledger, run_id, usage):
    ledger.on_llm_end(response(usage), run_id=run_id)


def test_complete_runs_sum_only_explicit_token_fields_without_model_names():
    ledger = _LangChainUsageLedger()
    for run_id in (uuid4(), uuid4()):
        start(ledger, run_id)
        finish(ledger, run_id, {**receipt(), "requests": 9, "estimated_cost_usd": 123, "details": PrivateValue()})
    assert ledger.usage() == {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10}
    assert "PRIVATE" not in json.dumps(ledger.usage(), allow_nan=False)


@pytest.mark.parametrize("field", ["input_tokens", "output_tokens", "total_tokens"])
@pytest.mark.parametrize("bad", [None, True, -1, 0.5, "5", float("inf"), PrivateValue()],
                         ids=["none", "bool", "negative", "fraction", "text", "inf", "private"])
@pytest.mark.parametrize("bad_first", [False, True])
def test_incomplete_fields_are_never_reported_as_partial_sums(field, bad, bad_first):
    ledger = _LangChainUsageLedger()
    damaged = {**receipt(), field: bad}
    for index, usage in enumerate([damaged, receipt()] if bad_first else [receipt(), damaged]):
        start(ledger, str(index))
        finish(ledger, str(index), usage)
    expected = {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10}
    expected.pop({"input_tokens": "prompt_tokens", "output_tokens": "completion_tokens"}.get(field, field))
    assert ledger.usage() == expected


def test_missing_usage_anywhere_makes_all_observed_totals_unknown():
    ledger = _LangChainUsageLedger()
    start(ledger, "first")
    finish(ledger, "first", receipt())
    start(ledger, "second")
    finish(ledger, "second", None)
    assert ledger.usage() == {}


def test_explicit_zero_is_distinct_from_absent_telemetry():
    ledger = _LangChainUsageLedger()
    start(ledger, "zero")
    finish(ledger, "zero", receipt(0, 0, 0))
    assert ledger.usage() == {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


@pytest.mark.parametrize("event", ["none", "pending", "error", "duplicate-start", "duplicate-end", "orphan-end",
                                   "orphan-error", "bad-id", "empty-id", "error-then-end"])
def test_ambiguous_or_incomplete_callback_lifecycles_are_not_complete_counts(event):
    ledger = _LangChainUsageLedger()
    if event == "none":
        assert ledger.usage() == {}
        return
    start(ledger, "complete")
    finish(ledger, "complete", receipt())
    if event == "pending":
        start(ledger, "pending")
    elif event in {"error", "error-then-end"}:
        start(ledger, "failed")
        ledger.on_llm_error(PrivateValue(), run_id="failed")
        if event == "error-then-end":
            finish(ledger, "failed", receipt())
    elif event == "duplicate-start":
        start(ledger, "complete")
    elif event == "duplicate-end":
        finish(ledger, "complete", receipt())
    elif event == "orphan-end":
        finish(ledger, "unknown", receipt())
    elif event == "orphan-error":
        ledger.on_llm_error(PrivateValue(), run_id="unknown")
    else:
        start(ledger, "" if event == "empty-id" else [])
    assert ledger.usage() == {}


@pytest.mark.parametrize("native", [None, PrivateValue(), SimpleNamespace(generations=[]),
                                    SimpleNamespace(generations=[[]]),
                                    SimpleNamespace(generations=[[SimpleNamespace()]]),
                                    SimpleNamespace(generations=[[SimpleNamespace(message=SimpleNamespace(type="AIMessageChunk"))]]),
                                    SimpleNamespace(generations=[[1], [2]]),
                                    SimpleNamespace(generations=[[1, 2]])],
                         ids=["none", "private", "empty", "empty-batch", "missing-message", "chunk", "batch", "alternatives"])
def test_malformed_or_ambiguous_responses_are_unknown(native):
    assert _langchain_receipt(native) == {}


def test_failing_metadata_access_does_not_capture_raw_exception():
    class Broken:
        @property
        def generations(self):
            raise ValueError("PRIVATE model payload")

    assert _langchain_receipt(Broken()) == {}


def test_snapshot_detaches_numeric_values_and_ignores_late_callbacks():
    ledger = _LangChainUsageLedger()
    values = receipt()
    start(ledger, "one")
    finish(ledger, "one", values)
    values["input_tokens"] = 1000
    captured = ledger.usage()
    assert captured == {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
    captured["total_tokens"] = 0
    start(ledger, "late")
    finish(ledger, "late", receipt())
    assert ledger.usage()["total_tokens"] == 5


def test_concurrent_callbacks_are_accounted_without_shared_run_state():
    ledger = _LangChainUsageLedger()

    def invoke(index):
        ledger.on_llm_start(PrivateValue(), PrivateValue(), run_id=str(index))
        finish(ledger, str(index), receipt())

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(invoke, range(50)))
    assert ledger.usage() == {"prompt_tokens": 100, "completion_tokens": 150, "total_tokens": 250}
    assert _LangChainUsageLedger().usage() == {}


@pytest.mark.parametrize("invalid_answer", [False, True])
def test_adapter_exports_only_after_answer_admission_and_reinitializes_collector(monkeypatch, invalid_answer):
    collectors, effects = [], []

    class Collector(_LangChainUsageLedger):
        def usage(self):
            if invalid_answer:
                pytest.fail("do not export telemetry for an invalid answer")
            return super().usage()

    def make_callback():
        value = Collector()
        collectors.append(value)
        return value

    def create_agent(**kwargs):
        def invoke(payload, *, config):
            callback = config["callbacks"][0]
            start(callback, "same-id-in-each-run")
            kwargs["tools"][0]()
            finish(callback, "same-id-in-each-run", receipt())
            return {"messages": [SimpleNamespace(type="ai", content=None if invalid_answer else "answer",
                                                 tool_calls=[], invalid_tool_calls=[])]}
        return SimpleNamespace(invoke=invoke)

    package, module = ModuleType("langchain"), ModuleType("langchain.agents")
    module.create_agent = create_agent
    monkeypatch.setitem(sys.modules, "langchain", package)
    monkeypatch.setitem(sys.modules, "langchain.agents", module)
    monkeypatch.setattr("dspy_security_bench.integrations.frameworks._langchain_usage_callback", make_callback)
    adapter = LangChainAdapter(model="fixture")
    tool = BenchTool("record", "Synthetic action", {}, lambda: effects.append(True) or "recorded")
    if invalid_answer:
        with pytest.raises(AgentResultError):
            adapter.run("query", [tool])
        assert effects == [True]
        return
    for _ in range(2):
        result = adapter.run("query", [tool])
        assert result.usage == {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
        assert result.tool_calls[0].result == "recorded"
    assert effects == [True, True] and collectors[0] is not collectors[1]
