"""Optimizer harness — runs a list of DSPy optimizers against a synthetic
trainset, produces a dict of named agent factories ready to plug into
`DSPyReActV2Element`.

v0.1 supports: "unoptimized", "bootstrap_fewshot", "miprov2".
GEPA support deferred to v0.2 (requires resolving its async/Pareto integration).

Usage:
    from dspy_security_bench.optimizers import build_agent_factories
    factories = build_agent_factories(
        trainset=[{"prompt": "...", "ground_truth": "..."}, ...],
        optimizers=["unoptimized", "bootstrap_fewshot"],
        suite_name="workspace",
        signature="query -> answer",
        lm=dspy.LM("openai/gpt-4o-mini"),
    )
    for name, factory in factories.items():
        agent = factory(tools=..., max_iters=10)
        # use with DSPyReActV2Element
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from copy import deepcopy
from typing import Any

import dspy
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from dspy_security_bench.adapters.agentdojo import _make_dspy_tool, make_reactv2_picklable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Trainset prep
# ---------------------------------------------------------------------------

def _tasks_to_dspy_examples(tasks: list[dict], input_field: str = "query") -> list[dspy.Example]:
    """Convert validator output → dspy.Example list."""
    examples = []
    for t in tasks:
        ex = dspy.Example(
            **{input_field: t["prompt"]},
            ground_truth=t["ground_truth"],
        ).with_inputs(input_field)
        examples.append(ex)
    return examples


# ---------------------------------------------------------------------------
# Default metric (placeholder; LLM-as-judge lands in its own module later)
# ---------------------------------------------------------------------------

def substring_match_metric(example, pred, trace=None) -> float:
    """v0.1 placeholder metric: does the agent's answer contain the ground truth?

    Handles two cases:
    - single-token ground truth → exact substring (case-insensitive)
    - multi-token ground truth → all tokens present (any order)

    Returns 1.0 if match, 0.0 otherwise.
    """
    answer = str(getattr(pred, "answer", "") or "").lower()
    gt = str(getattr(example, "ground_truth", "") or "").lower().strip()
    if not gt:
        return 0.0
    gt_stripped = gt.strip("\"'.,;:!? ")
    if not gt_stripped:
        return 0.0
    if gt_stripped in answer:
        return 1.0
    if gt_stripped.isdigit():
        return 1.0 if gt_stripped in answer else 0.0
    tokens = [t for t in gt_stripped.split() if t]
    if len(tokens) >= 2 and all(t in answer for t in tokens):
        return 1.0
    return 0.0


# ---------------------------------------------------------------------------
# Training-time tool binding
# ---------------------------------------------------------------------------

def _build_training_tools(suite_name: str, version: str = "v1"):
    """Build a set of dspy.Tools bound to a fresh suite env, for use during
    optimization. The same env is shared across all training examples.

    Reasoning: synthetic tasks are grounded in the suite's default env data
    (Option C decision), so training tools answering against that env produces
    answers that match the trainset's ground_truth.
    """
    suite = get_suite(version, suite_name)
    runtime = FunctionsRuntime(functions=suite.tools)
    env = suite.load_and_inject_default_environment({})
    return [_make_dspy_tool(fn, runtime, env) for fn in runtime.functions.values()]


# ---------------------------------------------------------------------------
# Agent factory builder
# ---------------------------------------------------------------------------

def _make_agent_factory(
    optimized_agent: dspy.ReActV2 | None,
    base_signature,
) -> Callable[..., dspy.ReActV2]:
    """Wrap an optimized ReActV2 (or None for unoptimized) into a factory that
    builds fresh ReActV2 instances with arbitrary tools but the optimized
    instructions and demos preserved."""

    if optimized_agent is None:
        # Unoptimized baseline: fresh agent each call
        def baseline_factory(tools, max_iters):
            agent = dspy.ReActV2(
                signature=base_signature,
                tools=tools,
                max_iters=max_iters,
            )
            make_reactv2_picklable(agent)
            return agent
        return baseline_factory

    # Pull optimized state off the inner Predict
    optimized_instructions = optimized_agent.react.signature.instructions
    optimized_demos = list(optimized_agent.react.demos)

    def factory(tools, max_iters):
        agent = dspy.ReActV2(
            signature=base_signature,
            tools=tools,
            max_iters=max_iters,
        )
        make_reactv2_picklable(agent)
        # Apply optimized state to the inner predictor
        agent.react.signature = agent.react.signature.with_instructions(optimized_instructions)
        agent.react.demos = list(optimized_demos)
        return agent

    return factory


# ---------------------------------------------------------------------------
# Optimizers
# ---------------------------------------------------------------------------

def _run_bootstrap_fewshot(
    student: dspy.ReActV2,
    trainset: list[dspy.Example],
    metric: Callable,
    **kwargs,
) -> dspy.ReActV2:
    teleprompter = dspy.BootstrapFewShot(
        metric=metric,
        max_bootstrapped_demos=kwargs.get("max_bootstrapped_demos", 4),
        max_labeled_demos=kwargs.get("max_labeled_demos", 4),
        max_rounds=kwargs.get("max_rounds", 1),
    )
    return teleprompter.compile(student=student, trainset=trainset)


def _run_miprov2(
    student: dspy.ReActV2,
    trainset: list[dspy.Example],
    metric: Callable,
    **kwargs,
) -> dspy.ReActV2:
    teleprompter = dspy.MIPROv2(
        metric=metric,
        auto=kwargs.get("auto", "light"),
        num_threads=kwargs.get("num_threads", 4),
    )
    return teleprompter.compile(student=student, trainset=trainset, requires_permission_to_run=False)


_OPTIMIZER_FNS = {
    "bootstrap_fewshot": _run_bootstrap_fewshot,
    "miprov2": _run_miprov2,
}


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def build_agent_factories(
    trainset: list[dict],
    optimizers: list[str],
    suite_name: str = "workspace",
    version: str = "v1",
    signature: str = "query -> answer",
    metric: Callable | None = None,
    lm: dspy.LM | None = None,
    max_iters_train: int = 10,
    optimizer_kwargs: dict[str, dict] | None = None,
) -> dict[str, Callable]:
    """Run each requested optimizer; return name → agent_factory dict.

    Args:
        trainset: list of {"prompt", "ground_truth"} dicts from the validator.
        optimizers: list of names in ("unoptimized", "bootstrap_fewshot", "miprov2").
        suite_name: AgentDojo suite name to bind training tools against.
        signature: dspy signature string for the agent — MUST have single output.
        metric: metric callable (example, pred, trace=None) -> float. Defaults
            to substring_match_metric.
        lm: dspy.LM to use during optimization. If None, expects current
            dspy.context to have one set.
        max_iters_train: max ReActV2 iterations during optimization.
        optimizer_kwargs: per-optimizer kwargs overrides.
    """
    metric = metric or substring_match_metric
    optimizer_kwargs = optimizer_kwargs or {}

    dspy_examples = _tasks_to_dspy_examples(trainset, input_field="query")
    train_tools = _build_training_tools(suite_name, version)

    factories: dict[str, Callable] = {}

    for opt_name in optimizers:
        if opt_name == "unoptimized":
            factories[opt_name] = _make_agent_factory(None, base_signature=signature)
            logger.info(f"  optimizer={opt_name} → baseline factory ready")
            continue

        if opt_name not in _OPTIMIZER_FNS:
            raise ValueError(
                f"Unknown optimizer {opt_name!r}. "
                f"Supported: {['unoptimized'] + list(_OPTIMIZER_FNS)}"
            )

        student = dspy.ReActV2(
            signature=signature,
            tools=train_tools,
            max_iters=max_iters_train,
        )
        make_reactv2_picklable(student)

        opt_fn = _OPTIMIZER_FNS[opt_name]
        opt_kw = optimizer_kwargs.get(opt_name, {})

        logger.info(f"  optimizer={opt_name} → starting compile (this can take a while)")
        if lm is not None:
            with dspy.context(lm=lm):
                compiled = opt_fn(student=student, trainset=dspy_examples, metric=metric, **opt_kw)
        else:
            compiled = opt_fn(student=student, trainset=dspy_examples, metric=metric, **opt_kw)
        logger.info(f"  optimizer={opt_name} → compile complete")

        factories[opt_name] = _make_agent_factory(compiled, base_signature=signature)

    return factories
