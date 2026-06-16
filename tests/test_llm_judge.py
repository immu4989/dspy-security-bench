"""Tests for the LLM-as-judge metric."""
from __future__ import annotations

import dspy
import pytest

from dspy_security_bench.llm_judge import LLMJudgeMetric


def _ex(gt: str):
    return dspy.Example(query="?", ground_truth=gt).with_inputs("query")


def _pred(answer: str):
    return dspy.Prediction(answer=answer)


def test_fast_path_hit_skips_llm():
    """When substring already matches, fast path returns 1.0 with no LLM call."""
    judge = LLMJudgeMetric(fast_path=True)
    # No dspy.context — proves no LLM call happens
    score = judge(_ex("10:00"), _pred("The meeting starts at 10:00 sharp."))
    assert score == 1.0


def test_fast_path_miss_falls_to_llm_judge_yes():
    judge = LLMJudgeMetric(fast_path=True)
    lm = dspy.utils.DummyLM([{"correct": True}])
    with dspy.context(lm=lm, adapter=dspy.ChatAdapter()):
        score = judge(_ex("10:00 AM"), _pred("ten in the morning"))
    assert score == 1.0


def test_fast_path_miss_falls_to_llm_judge_no():
    judge = LLMJudgeMetric(fast_path=True)
    lm = dspy.utils.DummyLM([{"correct": False}])
    with dspy.context(lm=lm, adapter=dspy.ChatAdapter()):
        score = judge(_ex("alice"), _pred("bob is the host"))
    assert score == 0.0


def test_llm_error_falls_back_to_substring():
    """When the judge LM raises, the metric should fall back to substring."""
    judge = LLMJudgeMetric(fast_path=True)
    # Empty DummyLM exhausts on the first judge call → AdapterParseError → substring fallback
    empty_lm = dspy.utils.DummyLM([])
    with dspy.context(lm=empty_lm, adapter=dspy.ChatAdapter()):
        # substring also misses → 0.0
        score = judge(_ex("11:00"), _pred("unrelated content"))
    assert score == 0.0


def test_disable_fast_path_forces_llm_call():
    """fast_path=False ignores substring even on hit."""
    judge = LLMJudgeMetric(fast_path=False)
    lm = dspy.utils.DummyLM([{"correct": False}])
    with dspy.context(lm=lm, adapter=dspy.ChatAdapter()):
        # substring would match, but fast_path is off so the judge sees it
        score = judge(_ex("10:00"), _pred("10:00 sharp"))
    assert score == 0.0


def test_empty_answer_returns_zero():
    judge = LLMJudgeMetric(fast_path=True)
    assert judge(_ex("anything"), _pred("")) == 0.0


def test_empty_ground_truth_returns_zero():
    judge = LLMJudgeMetric(fast_path=True)
    assert judge(_ex(""), _pred("any answer")) == 0.0


def test_judge_metric_name():
    judge = LLMJudgeMetric()
    assert judge.__name__ == "LLMJudgeMetric"
