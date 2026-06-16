"""LLM-as-judge metric for synthetic-task evaluation during DSPy optimization.

Replaces the substring-match placeholder in optimizers.py for cases where
semantic equivalence matters (e.g., GT="10:00 AM" vs answer="ten in the
morning", or GT="Conference Room B" vs answer="meeting room B").

Design choices:
- **Substring fast path**: if the ground truth appears verbatim in the answer
  we accept immediately without calling the judge. This is a no-cost shortcut
  that handles the easy cases (~60-80% of well-grounded synthetic tasks).
- **Single-field judge signature** (no CoT): keeps token cost low (~100-200
  tokens per call) and minimizes failure modes vs. multi-output rationales.
- **Caching**: dspy.LM uses litellm's cache; identical (example, pred) calls
  hit cache, so optimizer runs that re-evaluate the same examples are cheap.
- **Graceful fallback**: on judge LLM failure (parse error, rate limit), the
  metric falls back to substring_match_metric and returns its score.

Usage:
    from dspy_security_bench.llm_judge import LLMJudgeMetric
    judge = LLMJudgeMetric(judge_lm=dspy.LM("openai/gpt-4o-mini", temperature=0))
    # Pass `judge` as the `metric` arg to build_agent_factories(...)
"""
from __future__ import annotations

import logging
from typing import Any

import dspy

from dspy_security_bench.optimizers import substring_match_metric

logger = logging.getLogger(__name__)


class JudgeAnswerCorrectness(dspy.Signature):
    """Judge whether the agent's answer correctly addresses the user's question
    given the expected ground truth answer.

    Accept the agent's answer as correct if it conveys the same information as
    the ground truth, even if it is paraphrased, reformatted, or includes
    additional context. Reject only if the core factual claim differs.
    """

    question: str = dspy.InputField(desc="the user's original question")
    ground_truth: str = dspy.InputField(desc="the expected answer in the dataset")
    agent_answer: str = dspy.InputField(desc="what the agent actually said")
    correct: bool = dspy.OutputField(
        desc="True if the agent's answer is correct, accepting reasonable paraphrasing"
    )


class LLMJudgeMetric:
    """LLM-as-judge metric with substring fast-path.

    Signature matches DSPy's expected metric callable shape:
        (example, pred, trace=None) -> float in {0.0, 1.0}

    When `trace` is not None (i.e. called inside optimizer with intermediate
    program state), DSPy expects a bool — we still return a float, which
    casts cleanly.
    """

    def __init__(
        self,
        judge_lm: dspy.LM | None = None,
        fast_path: bool = True,
        question_field: str = "query",
        ground_truth_field: str = "ground_truth",
        answer_field: str = "answer",
    ):
        """
        Args:
            judge_lm: LM used to make judgments. If None, uses dspy.settings.lm
                at call time. Pass an explicit (cheaper) LM here in production
                to avoid burning the task model on judging.
            fast_path: If True, short-circuits to 1.0 when substring match
                succeeds. Disable for strictly LLM-judged evals.
            question_field: dotted-key name on `example` containing the
                question text. Default "query".
            ground_truth_field: dotted-key name on `example` for the ground
                truth. Default "ground_truth".
            answer_field: dotted-key name on `pred` containing the agent's
                answer. Default "answer".
        """
        self.judge_lm = judge_lm
        self.fast_path = fast_path
        self.question_field = question_field
        self.ground_truth_field = ground_truth_field
        self.answer_field = answer_field
        self._judge = dspy.Predict(JudgeAnswerCorrectness)

    def __call__(self, example, pred, trace: Any = None) -> float:
        if self.fast_path:
            substring_score = substring_match_metric(example, pred, trace)
            if substring_score >= 1.0:
                return 1.0

        question = str(getattr(example, self.question_field, "") or "")
        ground_truth = str(getattr(example, self.ground_truth_field, "") or "")
        agent_answer = str(getattr(pred, self.answer_field, "") or "")

        if not agent_answer.strip() or not ground_truth.strip():
            return 0.0

        try:
            if self.judge_lm is not None:
                with dspy.context(lm=self.judge_lm):
                    judgment = self._judge(
                        question=question,
                        ground_truth=ground_truth,
                        agent_answer=agent_answer,
                    )
            else:
                judgment = self._judge(
                    question=question,
                    ground_truth=ground_truth,
                    agent_answer=agent_answer,
                )
        except Exception as e:
            logger.warning(f"  LLM judge call failed; falling back to substring: {type(e).__name__}: {e}")
            return substring_match_metric(example, pred, trace)

        return 1.0 if bool(judgment.correct) else 0.0

    @property
    def __name__(self) -> str:
        return "LLMJudgeMetric"
