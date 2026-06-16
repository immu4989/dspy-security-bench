"""Tests for the optimizer harness + substring metric."""
from __future__ import annotations

import dspy
import pytest

from dspy_security_bench.optimizers import (
    _tasks_to_dspy_examples,
    build_agent_factories,
    substring_match_metric,
)


# ---------------------------------------------------------------------------
# substring_match_metric
# ---------------------------------------------------------------------------

def _ex(gt: str):
    return dspy.Example(query="?", ground_truth=gt).with_inputs("query")


def _pred(answer: str):
    return dspy.Prediction(answer=answer)


def test_substring_metric_exact_match():
    assert substring_match_metric(_ex("10:00"), _pred("The meeting starts at 10:00.")) == 1.0


def test_substring_metric_no_match():
    assert substring_match_metric(_ex("10:00"), _pred("Sometime in the morning")) == 0.0


def test_substring_metric_multi_token():
    score = substring_match_metric(
        _ex("alice bob"),
        _pred("The hosts are bob and alice and charlie"),
    )
    assert score == 1.0


def test_substring_metric_empty_ground_truth():
    assert substring_match_metric(_ex(""), _pred("anything")) == 0.0


def test_substring_metric_numeric_match():
    assert substring_match_metric(_ex("3"), _pred("There are 3 events.")) == 1.0


def test_substring_metric_handles_missing_answer_field():
    """If the prediction has no 'answer' attribute, score should be 0 (not crash)."""
    pred = dspy.Prediction(other="x")
    assert substring_match_metric(_ex("foo"), pred) == 0.0


# ---------------------------------------------------------------------------
# Trainset conversion
# ---------------------------------------------------------------------------

def test_tasks_to_dspy_examples():
    tasks = [
        {"prompt": "What time?", "ground_truth": "10:00"},
        {"prompt": "Who?", "ground_truth": "alice"},
    ]
    examples = _tasks_to_dspy_examples(tasks, input_field="query")
    assert len(examples) == 2
    assert examples[0].query == "What time?"
    assert examples[0].ground_truth == "10:00"
    # Check it's marked as an input
    assert "query" in examples[0].inputs()


# ---------------------------------------------------------------------------
# build_agent_factories — unoptimized path (no LM cost)
# ---------------------------------------------------------------------------

def test_build_factories_unoptimized_only():
    trainset = [
        {"prompt": "P1?", "ground_truth": "G1"},
        {"prompt": "P2?", "ground_truth": "G2"},
    ]
    factories = build_agent_factories(
        trainset=trainset,
        optimizers=["unoptimized"],
        suite_name="workspace",
    )
    assert set(factories.keys()) == {"unoptimized"}
    assert callable(factories["unoptimized"])


def test_unoptimized_factory_produces_working_agent():
    factories = build_agent_factories(
        trainset=[{"prompt": "P?", "ground_truth": "G"}],
        optimizers=["unoptimized"],
        suite_name="workspace",
    )
    factory = factories["unoptimized"]
    agent = factory(tools=[], max_iters=5)
    assert isinstance(agent, dspy.ReActV2)
    assert agent.max_iters == 5


def test_unknown_optimizer_raises():
    with pytest.raises(ValueError, match="Unknown optimizer"):
        build_agent_factories(
            trainset=[{"prompt": "P?", "ground_truth": "G"}],
            optimizers=["nonexistent_optimizer"],
            suite_name="workspace",
        )
