"""Missing cost/token observations must not turn into plausible partial totals."""
from types import SimpleNamespace

import pytest

from dspy_security_bench.agents import BenchTool, LiteLLMFunctionCallingAgent
from dspy_security_bench.agents.litellm_fc import _complete_usage


def response(*, usage=None, cost=None, tools=False):
    call = SimpleNamespace(id="call", function=SimpleNamespace(name="read", arguments="{}"))
    message = SimpleNamespace(content="done", tool_calls=[call] if tools else None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage,
                           _hidden_params={"response_cost": cost})


@pytest.mark.parametrize("reports", [
    [], [{}], [{"total_tokens": 5}, {}], [{}, {"total_tokens": 5}],
    [{"total_tokens": 5}, {}, {"total_tokens": 7}],
])
def test_missing_data_stays_unknown_regardless_of_order(reports):
    assert _complete_usage(reports) == {}


def test_known_fields_sum_independently_without_imputing_missing_fields():
    result = _complete_usage([
        {"total_tokens": 3, "estimated_cost_usd": 0.1, "prompt_tokens": 1},
        {"total_tokens": 4, "estimated_cost_usd": 0.2},
    ])
    assert result["total_tokens"] == 7
    assert result["estimated_cost_usd"] == pytest.approx(0.3)
    assert "prompt_tokens" not in result


def test_explicit_zero_is_known_not_missing():
    assert _complete_usage([{"total_tokens": 0}, {"total_tokens": 0}]) == {"total_tokens": 0}


def test_finite_per_response_cost_can_overflow_and_total_remains_unknown():
    assert _complete_usage([{"estimated_cost_usd": 1e308, "total_tokens": 2},
                            {"estimated_cost_usd": 1e308, "total_tokens": 3}]) == {"total_tokens": 5}


@pytest.mark.parametrize("missing_at", [0, 1, 2])
def test_real_loop_does_not_publish_partial_provider_cost(monkeypatch, missing_at):
    import litellm

    responses = [response(usage={"total_tokens": 3}, cost=None if i == missing_at else 0.25, tools=i < 2)
                 for i in range(3)]
    monkeypatch.setattr(litellm, "completion", lambda **kwargs: responses.pop(0))
    result = LiteLLMFunctionCallingAgent("fixture", max_iters=3).run("query", [BenchTool("read", "read", {}, lambda: "ok")])
    assert result.usage == {"total_tokens": 9}


def test_final_answer_response_participates_in_usage_coverage(monkeypatch):
    import litellm

    responses = [response(usage={"total_tokens": 3}, cost=0.25, tools=True),
                 response(usage=None, cost=None)]
    monkeypatch.setattr(litellm, "completion", lambda **kwargs: responses.pop(0))
    result = LiteLLMFunctionCallingAgent("fixture", max_iters=1).run("query", [BenchTool("read", "read", {}, lambda: "ok")])
    assert result.final_answer == "done" and result.usage == {}


@pytest.mark.parametrize("invalid", [True, -1, "3", float("nan"), float("inf")])
def test_invalid_usage_in_one_response_invalidates_only_affected_total(monkeypatch, invalid):
    import litellm

    responses = [response(usage={"total_tokens": 3}, cost=0.1, tools=True),
                 response(usage={"total_tokens": invalid}, cost=0.1)]
    monkeypatch.setattr(litellm, "completion", lambda **kwargs: responses.pop(0))
    result = LiteLLMFunctionCallingAgent("fixture").run("query", [BenchTool("read", "read", {}, lambda: "ok")])
    assert result.usage == {"estimated_cost_usd": 0.2}


def test_complete_provider_usage_still_sums_and_run_state_is_local(monkeypatch):
    import litellm

    responses = [response(usage={"total_tokens": 3}, cost=0.1, tools=True),
                 response(usage={"total_tokens": 4}, cost=0.2), response()]
    monkeypatch.setattr(litellm, "completion", lambda **kwargs: responses.pop(0))
    agent = LiteLLMFunctionCallingAgent("fixture")
    first = agent.run("query", [BenchTool("read", "read", {}, lambda: "ok")])
    assert first.usage["total_tokens"] == 7
    assert first.usage["estimated_cost_usd"] == pytest.approx(0.3)
    assert agent.run("next", []).usage == {}
