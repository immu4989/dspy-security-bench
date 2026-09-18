from types import SimpleNamespace

import pandas as pd
import pytest

from dspy_security_bench.runner import _run_attack_matrix, _suite_results_to_rows, summarize


def observations():
    return {"utility_results": {("u", "i"): True}, "security_results": {("u", "i"): False}}


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-utility",
        "missing-security",
        "empty",
        "wrong-pair",
        "bad-key",
        "none",
        "integer",
        "text",
    ],
)
def test_missing_or_nonboolean_observations_are_not_coerced_to_secure(mutation):
    result = observations()
    if mutation.startswith("missing-"):
        result.pop(mutation.removeprefix("missing-") + "_results")
    elif mutation == "empty":
        result = {"utility_results": {}, "security_results": {}}
    elif mutation == "wrong-pair":
        result["security_results"] = {("u", "other"): False}
    elif mutation == "bad-key":
        result = {"utility_results": {"bad": True}, "security_results": {"bad": False}}
    else:
        result["security_results"][("u", "i")] = {"none": None, "integer": 0, "text": "false"}[
            mutation
        ]
    with pytest.raises(ValueError):
        _suite_results_to_rows("fixture", "direct", result)


@pytest.mark.parametrize("expected", [{("u", "i"), ("u2", "i")}, {("u2", "i")}, set()])
def test_exact_matrix_rejects_omissions_substitutions_and_unrequested_rows(expected):
    with pytest.raises(ValueError, match="matrix exactly"):
        _suite_results_to_rows("fixture", "direct", observations(), expected_pairs=expected)


def matrix(monkeypatch, result, *, is_dos=False, users=None, injections=None):
    suite = SimpleNamespace(
        user_tasks={"u": object(), "u2": object()}, injection_tasks={"i": object(), "i2": object()}
    )
    monkeypatch.setattr(
        "dspy_security_bench.runner.load_attack",
        lambda *args: SimpleNamespace(is_dos_attack=is_dos),
    )
    monkeypatch.setattr(
        "dspy_security_bench.runner.benchmark_suite_with_injections", lambda **kwargs: result
    )
    return _run_attack_matrix(
        object(),
        suite,
        ["direct"],
        "agent",
        "fixture",
        "none",
        users,
        injections,
        None,
        True,
        False,
    )


def test_partial_benchmark_cannot_shrink_the_requested_denominator(monkeypatch):
    with pytest.raises(ValueError, match="matrix exactly"):
        matrix(monkeypatch, observations())


def test_selected_matrix_is_accepted(monkeypatch):
    rows = matrix(monkeypatch, observations(), users=["u"], injections=["i"])
    assert len(rows) == 1
    assert rows[0]["agent"] == "fixture"


def test_agentdojo_dos_single_injection_semantics_are_preserved(monkeypatch):
    rows = matrix(monkeypatch, observations(), is_dos=True, users=["u"], injections=["i2"])
    assert rows[0]["injection_task_id"] == "i"


@pytest.mark.parametrize("selected", [[], ["u", "u"], ["unknown"], "u", [None]])
def test_invalid_task_selection_fails_before_benchmark(monkeypatch, selected):
    with pytest.raises(ValueError):
        matrix(monkeypatch, observations(), users=selected)


@pytest.mark.parametrize(
    "column,value",
    [
        ("security", None),
        ("security", float("nan")),
        ("utility", 0.5),
        ("utility", "1"),
        ("injection_succeeded", 2),
        ("agent", None),
    ],
)
def test_aggregation_does_not_silently_drop_missing_measurements(column, value):
    rows = [
        {
            "agent": "fixture",
            "attack": "direct",
            "utility": 1,
            "security": 1,
            "injection_succeeded": 0,
        },
        {
            "agent": "fixture",
            "attack": "direct",
            "utility": 1,
            "security": 1,
            "injection_succeeded": 0,
        },
    ]
    rows[1][column] = value
    with pytest.raises(ValueError):
        summarize(pd.DataFrame(rows))


def test_boolean_security_and_injection_success_cannot_both_be_true():
    with pytest.raises(ValueError, match="complement"):
        summarize(
            pd.DataFrame(
                [
                    {
                        "agent": "a",
                        "attack": "x",
                        "utility": True,
                        "security": True,
                        "injection_succeeded": True,
                    }
                ]
            )
        )
