"""Tests for the evaluation runner."""
from __future__ import annotations

import types
from unittest.mock import patch

import pandas as pd
import pytest

from dspy_security_bench.runner import _suite_results_to_rows, evaluate_factories, summarize


# ---------------------------------------------------------------------------
# _suite_results_to_rows
# ---------------------------------------------------------------------------

def test_suite_results_to_rows_basic_shape():
    fake = {
        "utility_results": {
            ("user_task_0", "injection_task_0"): True,
            ("user_task_0", "injection_task_1"): False,
            ("user_task_1", "injection_task_0"): True,
        },
        "security_results": {
            ("user_task_0", "injection_task_0"): False,  # injection failed → security good
            ("user_task_0", "injection_task_1"): True,   # injection succeeded → security bad
            ("user_task_1", "injection_task_0"): False,
        },
    }
    rows = _suite_results_to_rows("unoptimized", "direct", fake)
    assert len(rows) == 3

    # Row for (user_task_0, injection_task_0)
    r = next(r for r in rows
             if r["user_task_id"] == "user_task_0" and r["injection_task_id"] == "injection_task_0")
    assert r["optimizer"] == "unoptimized"
    assert r["attack"] == "direct"
    assert r["utility"] == 1
    assert r["injection_succeeded"] == 0
    assert r["security"] == 1


def test_security_is_inverse_of_injection_succeeded():
    fake = {
        "utility_results": {("u", "i"): True},
        "security_results": {("u", "i"): True},  # injection SUCCEEDED
    }
    rows = _suite_results_to_rows("opt", "atk", fake)
    assert rows[0]["injection_succeeded"] == 1
    assert rows[0]["security"] == 0


def test_suite_results_with_missing_keys_treated_as_false():
    """If a (user, injection) combo appears in utility but not security, security defaults to good."""
    fake = {
        "utility_results": {("u", "i"): True},
        "security_results": {},  # empty
    }
    rows = _suite_results_to_rows("opt", "atk", fake)
    assert rows[0]["injection_succeeded"] == 0
    assert rows[0]["security"] == 1


# ---------------------------------------------------------------------------
# summarize
# ---------------------------------------------------------------------------

def test_summarize_aggregates_correctly():
    df = pd.DataFrame([
        {"optimizer": "a", "attack": "x", "user_task_id": "u0", "injection_task_id": "i0",
         "utility": 1, "injection_succeeded": 0, "security": 1},
        {"optimizer": "a", "attack": "x", "user_task_id": "u1", "injection_task_id": "i0",
         "utility": 0, "injection_succeeded": 1, "security": 0},
        {"optimizer": "b", "attack": "x", "user_task_id": "u0", "injection_task_id": "i0",
         "utility": 1, "injection_succeeded": 1, "security": 0},
    ])
    s = summarize(df)
    a_row = s[(s["optimizer"] == "a") & (s["attack"] == "x")].iloc[0]
    assert a_row["utility_rate"] == 0.5
    assert a_row["security_rate"] == 0.5
    assert a_row["injection_success_rate"] == 0.5
    assert a_row["n_runs"] == 2

    b_row = s[(s["optimizer"] == "b") & (s["attack"] == "x")].iloc[0]
    assert b_row["utility_rate"] == 1.0
    assert b_row["security_rate"] == 0.0
    assert b_row["n_runs"] == 1


# ---------------------------------------------------------------------------
# evaluate_factories — end-to-end orchestration with mocked benchmark call
# ---------------------------------------------------------------------------

def test_evaluate_factories_orchestration():
    def factory_a(tools, max_iters):
        return types.SimpleNamespace(name="a")

    def factory_b(tools, max_iters):
        return types.SimpleNamespace(name="b")

    factories = {"unoptimized": factory_a, "bootstrap_fewshot": factory_b}

    call_count = {"n": 0}

    def fake_benchmark(*args, **kwargs):
        call_count["n"] += 1
        seed = call_count["n"]
        return {
            "utility_results": {
                ("user_task_0", "injection_task_0"): bool(seed % 2),
                ("user_task_1", "injection_task_0"): True,
            },
            "security_results": {
                ("user_task_0", "injection_task_0"): False,
                ("user_task_1", "injection_task_0"): bool((seed + 1) % 2),
            },
            "injection_tasks_utility_results": {},
        }

    with patch("dspy_security_bench.runner.benchmark_suite_with_injections",
               side_effect=fake_benchmark), \
         patch("dspy_security_bench.runner.load_attack",
               side_effect=lambda name, suite, pipeline: types.SimpleNamespace(name=name)):
        df = evaluate_factories(
            factories=factories,
            suite_name="workspace",
            attacks=["direct", "important_instructions"],
            user_task_ids=["user_task_0", "user_task_1"],
            injection_task_ids=["injection_task_0"],
        )

    # 2 factories × 2 attacks = 4 benchmark calls
    assert call_count["n"] == 4
    # Each call yields 2 rows; total 8
    assert len(df) == 8
    assert set(df["optimizer"].unique()) == {"unoptimized", "bootstrap_fewshot"}
    assert set(df["attack"].unique()) == {"direct", "important_instructions"}
    # security must equal NOT injection_succeeded
    assert ((df["security"] + df["injection_succeeded"]) == 1).all()
