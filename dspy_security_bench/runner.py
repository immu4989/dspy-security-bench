"""Evaluation runner — orchestrates AgentDojo benchmark runs across a dict of
agent factories (from `build_agent_factories`) and a list of attacks.

Returns a pandas DataFrame with one row per (optimizer, attack, user_task,
injection_task) combination, columns: utility (did the agent complete the
user task?) and security (did the injection NOT succeed?).

Usage:
    from dspy_security_bench.runner import evaluate_factories
    df = evaluate_factories(
        factories={"unoptimized": baseline_factory, "miprov2": opt_factory},
        suite_name="workspace",
        attacks=["direct", "important_instructions"],
        user_task_ids=["user_task_0", "user_task_1", "user_task_3"],
        injection_task_ids=["injection_task_0"],
        max_iters=10,
    )
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pandas as pd
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery
from agentdojo.attacks import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.task_suite.load_suites import get_suite

from dspy_security_bench.adapters import DSPyReActV2Element

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline construction
# ---------------------------------------------------------------------------

def _build_pipeline(
    factory: Callable,
    pipeline_name: str,
    max_iters: int,
    output_field: str | None,
) -> AgentPipeline:
    """Wrap a DSPy factory in the standard AgentDojo pipeline:
    [InitQuery, DSPyReActV2Element(factory)]."""
    element = DSPyReActV2Element(
        agent_factory=factory,
        max_iters=max_iters,
        output_field=output_field,
    )
    pipeline = AgentPipeline([InitQuery(), element])
    pipeline.name = pipeline_name  # attacks use this for logging / attack targeting
    return pipeline


# ---------------------------------------------------------------------------
# Results → DataFrame
# ---------------------------------------------------------------------------

def _suite_results_to_rows(
    optimizer_name: str,
    attack_name: str,
    suite_results: dict,
) -> list[dict]:
    """Flatten a SuiteResults dict into per-(user_task, injection_task) rows.

    SuiteResults shape (from agentdojo.benchmark):
      utility_results: dict[(user_task_id, injection_task_id), bool]
      security_results: dict[(user_task_id, injection_task_id), bool]

    Note on `security`: AgentDojo's convention is
      security_results[k] == True  ⇒  injection SUCCEEDED (bad for the agent)
      security_results[k] == False ⇒  injection failed (good for the agent)
    We invert it here so a higher number is better, consistent with utility.
    """
    rows = []
    utility = suite_results.get("utility_results", {})
    security = suite_results.get("security_results", {})

    all_keys = set(utility) | set(security)
    for user_task_id, injection_task_id in sorted(all_keys):
        rows.append({
            "optimizer": optimizer_name,
            "attack": attack_name,
            "user_task_id": user_task_id,
            "injection_task_id": injection_task_id,
            "utility": int(bool(utility.get((user_task_id, injection_task_id), False))),
            "injection_succeeded": int(bool(security.get((user_task_id, injection_task_id), False))),
            "security": int(not bool(security.get((user_task_id, injection_task_id), False))),
        })
    return rows


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def evaluate_factories(
    factories: dict[str, Callable],
    suite_name: str = "workspace",
    version: str = "v1",
    attacks: Sequence[str] = ("direct",),
    user_task_ids: Sequence[str] | None = None,
    injection_task_ids: Sequence[str] | None = None,
    max_iters: int = 10,
    output_field: str | None = None,
    logdir: Path | None = None,
    force_rerun: bool = True,
    verbose: bool = False,
) -> pd.DataFrame:
    """Run each (factory, attack) combination across the suite's user-task
    × injection-task matrix; return a flat DataFrame of results.

    Args:
        factories: mapping of optimizer name → agent_factory callable.
        suite_name: AgentDojo suite ("workspace", "banking", "travel", "slack").
        attacks: attack names from agentdojo.attacks.ATTACKS keys
            ("direct", "important_instructions", "tool_knowledge", ...).
        user_task_ids: subset of user task IDs to evaluate (default: all).
        injection_task_ids: subset of injection task IDs (default: all).
        max_iters: max ReActV2 iterations per task.
        output_field: signature output field name (default: inferred).
        logdir: directory for AgentDojo's per-task trace logs (default: temp).
        force_rerun: ignore cached AgentDojo results.
        verbose: AgentDojo verbose mode.
    """
    suite = get_suite(version, suite_name)
    all_rows: list[dict] = []

    for optimizer_name, factory in factories.items():
        pipeline_name = f"dspy_reactv2_{optimizer_name}"
        pipeline = _build_pipeline(
            factory=factory,
            pipeline_name=pipeline_name,
            max_iters=max_iters,
            output_field=output_field,
        )

        for attack_name in attacks:
            logger.info(f"  running optimizer={optimizer_name} × attack={attack_name}")
            attack = load_attack(attack_name, suite, pipeline)

            suite_results = benchmark_suite_with_injections(
                agent_pipeline=pipeline,
                suite=suite,
                attack=attack,
                logdir=logdir,
                force_rerun=force_rerun,
                user_tasks=list(user_task_ids) if user_task_ids else None,
                injection_tasks=list(injection_task_ids) if injection_task_ids else None,
                verbose=verbose,
            )

            rows = _suite_results_to_rows(
                optimizer_name=optimizer_name,
                attack_name=attack_name,
                suite_results=suite_results,
            )
            all_rows.extend(rows)

    return pd.DataFrame(all_rows)


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    """Quick aggregation: utility + security rates per (optimizer, attack)."""
    grouped = df.groupby(["optimizer", "attack"]).agg(
        utility_rate=("utility", "mean"),
        security_rate=("security", "mean"),
        injection_success_rate=("injection_succeeded", "mean"),
        n_runs=("utility", "size"),
    ).reset_index()
    return grouped
