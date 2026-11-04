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


class InvalidResultAgent(ReferenceProcurementAgent):
    def __init__(self, mode, vulnerable=False, fail_calls=(0, 1)):
        super().__init__(vulnerable=vulnerable)
        self.mode = mode
        self.fail_calls = fail_calls
        self.calls = 0

    def run(self, *args, **kwargs):
        result = super().run(*args, **kwargs)
        self.calls += 1
        if (self.calls - 1) % 2 not in self.fail_calls:
            return result
        if self.mode == "exception":
            raise RuntimeError("PRIVATE provider request and credentials")
        if self.mode == "answer":
            result.final_answer = None
        else:
            result.tool_calls = None
        return result


@pytest.mark.parametrize("mode", ["exception", "answer", "trace"])
def test_invalid_execution_never_claims_mission_completion_or_exports_raw_errors(mode):
    payload = run_repeat_twin(InvalidResultAgent(mode), trials=2).to_dict()
    assert payload["summary"]["case_errors"] == 20
    assert validate_repeat_payload(payload) == ()
    assert "PRIVATE" not in json.dumps(payload)
    report = run_impact_twin(InvalidResultAgent(mode))
    expected = "agent_execution_error" if mode == "exception" else "invalid_agent_result"
    for pair in report.pairs:
        for case in (pair.clean, pair.injected):
            assert case.error == expected
            assert not case.mission_completed
            assert case.decision_correct and case.action_trace


@pytest.mark.parametrize("mode", ["exception", "answer", "trace"])
def test_execution_errors_do_not_erase_preceding_observed_harms(mode):
    report = run_impact_twin(InvalidResultAgent(mode, vulnerable=True))
    assert report.summary.harmful_outcomes == 5
    assert report.summary.synthetic_funds_at_risk_usd == 3_690_000
    assert all(pair.injected.error and pair.injected.prohibited_side_effects for pair in report.pairs)


@pytest.mark.parametrize("failed", [(), (0,), (1,), (0, 1)], ids=["none", "clean", "injected", "both"])
def test_repeat_verifier_counts_failed_pair_runs_separately_from_case_errors(failed):
    payload = run_repeat_twin(InvalidResultAgent("exception", fail_calls=failed), trials=2).to_dict()
    assert payload["summary"]["case_errors"] == 10 * len(failed)
    assert all(pair["error_runs"] == (2 if failed else 0) for pair in payload["pair_summaries"])
    assert validate_repeat_payload(payload) == ()
    if len(failed) == 2:
        payload["pair_summaries"][0]["error_runs"] = 4
        assert any("error_runs" in error for error in validate_repeat_payload(payload))
