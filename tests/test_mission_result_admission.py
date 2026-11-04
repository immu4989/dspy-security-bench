"""Mission admission preserves observed harms but does not score broken return values."""

import json
from copy import deepcopy

import pytest

from dspy_security_bench.agents import normalize_usage
from dspy_security_bench.incident.agents import ReferenceIncidentAgent
from dspy_security_bench.incident.benchmark import run_incident_twin, verify_incident_report
from dspy_security_bench.incident.repeat import (
    run_repeat_incident_twin,
    verify_repeat_incident_report,
)
from dspy_security_bench.mission.agents import ReferenceSourceAgent
from dspy_security_bench.mission.benchmark import run_mission_pack, verify_mission_report
from dspy_security_bench.mission.loader import load_mission_pack
from dspy_security_bench.mission.repeat import run_repeat_mission_pack, verify_repeat_source_report


@pytest.fixture(params=["incident", "source"])
def family(request):
    return request.param


def factory(family, mode="unchanged", usage=None, vulnerable=False):
    base = ReferenceIncidentAgent if family == "incident" else ReferenceSourceAgent

    class FixtureAgent(base):
        def run(self, *args, **kwargs):
            result = super().run(*args, **kwargs)
            if mode == "answer":
                result.final_answer = None
            elif mode == "trace":
                result.tool_calls = None
            elif mode == "object":
                return None
            elif mode == "exception":
                raise RuntimeError("PRIVATE provider request and credentials")
            elif mode == "usage":
                result.usage = usage
            elif mode == "empty":
                result.final_answer = ""
            return result

    return lambda: FixtureAgent(vulnerable=vulnerable)


def run(family, create, repeated=False):
    if repeated:
        if family == "incident":
            return run_repeat_incident_twin(create, trials=2).to_dict()
        return run_repeat_mission_pack(create, load_mission_pack("source-twin"), trials=2).to_dict()
    if family == "incident":
        return run_incident_twin(create(), agent_factory=create).to_dict()
    return run_mission_pack(create(), load_mission_pack("source-twin"), agent_factory=create).to_dict()


def verify(family, payload, repeated=False):
    if repeated:
        return (verify_repeat_incident_report if family == "incident" else verify_repeat_source_report)(payload)
    return (verify_incident_report if family == "incident" else verify_mission_report)(payload)


def cases(payload):
    return [case for pair in payload["pairs"] for case in (pair["clean"], pair["injected"])]


@pytest.mark.parametrize("mode", ["answer", "trace", "object", "exception"])
def test_required_result_failures_are_not_mission_completion_and_replay(family, mode):
    report = run(family, factory(family, mode))
    expected = "agent_execution_error" if mode == "exception" else "invalid_agent_result"
    assert all(case["error"] == expected and not case["mission_completed"] for case in cases(report))
    assert all(case["action_trace"] for case in cases(report))
    assert report["summary"]["case_errors"] == 10
    assert "PRIVATE" not in json.dumps(report, allow_nan=False)
    assert verify(family, report) == ()
    repeated = run(family, factory(family, mode), repeated=True)
    assert repeated["summary"]["case_errors"] == 20
    assert verify(family, repeated, repeated=True) == ()


@pytest.mark.parametrize("mode", ["answer", "trace", "object", "exception"])
def test_required_result_failures_preserve_preceding_observed_harms(family, mode):
    reference = run(family, factory(family, vulnerable=True))
    report = run(family, factory(family, mode, vulnerable=True))
    harm_key = "prohibited_side_effects" if family == "incident" else "prohibited_outcomes"
    assert any(case[harm_key] for case in cases(reference))
    for before, after in zip(cases(reference), cases(report), strict=True):
        assert before["action_trace"] == after["action_trace"]
        assert before[harm_key] == after[harm_key]
        assert after["error"] and not after["mission_completed"]
    assert verify(family, report) == ()


@pytest.mark.parametrize("usage", [None, [], "PRIVATE", {"total_tokens": True}, {"total_tokens": -1},
                                   {"total_tokens": 1.5}, {"estimated_cost_usd": float("inf")},
                                   {"estimated_cost_usd": float("nan")}, {"estimated_cost_usd": 10**1000}],
                         ids=["none", "array", "text", "boolean", "negative", "fractional-count",
                              "infinite-cost", "nan-cost", "oversized-cost"])
def test_invalid_optional_usage_is_unknown_not_task_failure(family, usage):
    reference = run(family, factory(family))
    report = run(family, factory(family, "usage", usage=usage))
    assert all(case["usage"] == {} and case["error"] is None for case in cases(report))
    for before, after in zip(cases(reference), cases(report), strict=True):
        assert {k: v for k, v in before.items() if k != "usage"} == {k: v for k, v in after.items() if k != "usage"}
    json.dumps(report, allow_nan=False)
    assert verify(family, report) == ()


def test_valid_fields_survive_bad_optional_neighbors_and_remain_json_portable(family):
    usage = {"prompt_tokens": 0, "completion_tokens": 7, "total_tokens": False,
             "estimated_cost_usd": 0, "PRIVATE_EXTENSION": 42}
    expected = {"prompt_tokens": 0, "completion_tokens": 7, "estimated_cost_usd": 0.0}
    report = run(family, factory(family, "usage", usage=usage), repeated=True)
    assert report["summary"]["case_errors"] == 0
    assert all(case["usage"] == expected for trial in report["trials"] for case in cases(trial))
    assert "PRIVATE_EXTENSION" not in json.dumps(report, allow_nan=False)
    assert verify(family, report, repeated=True) == ()


def test_intentional_empty_answer_is_valid_and_scored_normally(family):
    report = run(family, factory(family, "empty"))
    assert all(case["final_answer"] == "" and case["error"] is None for case in cases(report))
    assert all(case["mission_completed"] for case in cases(report))
    assert verify(family, report) == ()


def test_historical_optional_numeric_fields_are_not_rewritten_on_replay(family):
    report = run(family, factory(family))
    for case in cases(report):
        case["usage"] = {"requests": 1, "duration_ms": 1.5}
    original = deepcopy(report)
    assert verify(family, report) == ()
    assert report == original


def test_shared_usage_helper_keeps_existing_procurement_contract():
    from dspy_security_bench.procurement.benchmark import _normalize_usage

    assert _normalize_usage is normalize_usage
    raw = {"prompt_tokens": 0, "completion_tokens": 2, "estimated_cost_usd": 0.2}
    assert normalize_usage(raw) == raw
    assert "total_tokens" not in normalize_usage(raw)
