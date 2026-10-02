"""Invalid optional usage metadata must not change measured task outcomes."""

import json
from types import SimpleNamespace

import pytest

from dspy_security_bench.procurement.agents import ReferenceProcurementAgent
from dspy_security_bench.procurement.benchmark import (
    _normalize_usage,
    _reported_total,
    _summarize_usage,
    run_impact_twin,
)
from dspy_security_bench.procurement.repeat import (
    _usage_summary,
    _usage_summary_payload,
    run_repeat_twin,
    validate_repeat_payload,
)
from dspy_security_bench.procurement.repeat_control import _usage_payload


class CostMetadataAgent(ReferenceProcurementAgent):
    def __init__(self, cost):
        super().__init__(vulnerable=False)
        self.cost = cost

    def run(self, *args, **kwargs):
        result = super().run(*args, **kwargs)
        result.usage = {"total_tokens": 7, "estimated_cost_usd": self.cost}
        return result


@pytest.mark.parametrize("cost", [10**1000, float("inf"), float("nan"), -1, True, "private-value"])
def test_invalid_optional_cost_does_not_turn_completed_tasks_into_errors(cost):
    report = run_impact_twin(CostMetadataAgent(cost))
    cases = [case for pair in report.pairs for case in (pair.clean, pair.injected)]
    assert all(case.error is None and case.mission_completed for case in cases)
    assert all(case.usage == {"total_tokens": 7} for case in cases)
    assert report.summary.usage.total_tokens == 70
    assert report.summary.usage.estimated_cost_usd is None
    json.dumps(report.to_dict(), allow_nan=False)


def test_overflow_is_unknown_in_runtime_and_recomputed_usage():
    values = [{"total_tokens": 7, "estimated_cost_usd": 1e308}] * 2
    cases = [SimpleNamespace(usage=value) for value in values]
    expected = {"total_cases": 2, "reported_cases": 2, "total_tokens": 14,
                "estimated_cost_usd": None, "prompt_tokens": None, "completion_tokens": None}
    assert _summarize_usage(cases).to_dict() == expected
    assert _usage_summary(cases).to_dict() == expected
    assert _usage_summary_payload([{"usage": value} for value in values]) == expected
    assert _reported_total([10**1000, 1.0]) is None
    assert _reported_total([10**1000, 1]) == 10**1000 + 1


def test_overflow_repeat_report_is_portable_and_replays_without_inventing_zero_cost():
    result = run_repeat_twin(CostMetadataAgent(1e308), trials=2).to_dict()
    assert result["summary"]["usage"]["estimated_cost_usd"] is None
    assert result["summary"]["case_errors"] == 0
    json.dumps(result, allow_nan=False)
    assert validate_repeat_payload(result) == ()


def test_control_cost_overflow_cannot_generate_a_savings_delta():
    controls = [{"baseline": {"summary": {"usage": {
        "reported_cases": 10, "total_tokens": 70, "estimated_cost_usd": 1e308}}},
        "controlled": {"summary": {"usage": {
        "reported_cases": 10, "total_tokens": 60, "estimated_cost_usd": 0.1}}}}] * 2
    result = _usage_payload(controls)
    assert result["baseline_estimated_cost_usd"] is None
    assert result["controlled_estimated_cost_usd"] == 0.2
    assert result["estimated_cost_delta_usd"] is None
    assert result["total_tokens_delta"] == -20
    json.dumps(result, allow_nan=False)


def test_zero_and_historical_partial_subtotals_remain_distinct_from_unknown():
    assert _normalize_usage({"estimated_cost_usd": 0}) == {"estimated_cost_usd": 0.0}
    assert _reported_total([]) is None
    assert _reported_total([0.0, 0.0]) == 0.0
    cases = [SimpleNamespace(usage={}), SimpleNamespace(usage={"estimated_cost_usd": 0.1})]
    summary = _summarize_usage(cases)
    assert summary.reported_cases == 1 and summary.total_cases == 2
    assert summary.estimated_cost_usd == 0.1  # Reported subtotal, not a complete bill.
