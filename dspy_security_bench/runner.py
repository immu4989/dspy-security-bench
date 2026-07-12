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
from agentdojo.logging import NullLogger
from agentdojo.task_suite.load_suites import get_suite

# Monkey-patch fix for AgentDojo bug: NullLogger only sets `logdir` inside
# `__enter__`, but TraceLogger does `delegate.logdir or ...` on the result of
# `Logger.get()`, which returns an un-entered NullLogger when no context is
# active. AttributeError. Adding `logdir = None` as a class attribute makes
# accessing `.logdir` return None safely, and TraceLogger falls back to its
# default `runs/` directory.
NullLogger.logdir = None

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
    defense=None,
) -> AgentPipeline:
    """Wrap a DSPy factory in the standard AgentDojo pipeline:
    [InitQuery, DSPyReActV2Element(factory, defense=defense)]."""
    element = DSPyReActV2Element(
        agent_factory=factory,
        max_iters=max_iters,
        output_field=output_field,
        defense=defense,
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
    defense_name: str = "none",
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
            "defense": defense_name,
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
    defenses: Sequence[str] = ("none",),
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
    from dspy_security_bench.defenses import get_defense

    suite = get_suite(version, suite_name)
    all_rows: list[dict] = []

    for optimizer_name, factory in factories.items():
        for defense_name in defenses:
            defense = get_defense(defense_name)
            # AgentDojo's `important_instructions` attack scans the pipeline
            # name for known model keys from agentdojo.models.MODEL_NAMES (e.g.
            # "gpt-4o-mini-2024-07-18"). We keep that key so the attack targets
            # consistently, and append optimizer+defense so each run's log/cache
            # key is distinct.
            pipeline_name = (
                f"gpt-4o-mini-2024-07-18_dspy_reactv2_{optimizer_name}_def-{defense_name}"
            )
            pipeline = _build_pipeline(
                factory=factory,
                pipeline_name=pipeline_name,
                max_iters=max_iters,
                output_field=output_field,
                defense=defense,
            )
            all_rows.extend(_run_attack_matrix(
                pipeline=pipeline,
                suite=suite,
                attacks=attacks,
                subject_col="optimizer",
                subject_name=optimizer_name,
                defense_name=defense_name,
                user_task_ids=user_task_ids,
                injection_task_ids=injection_task_ids,
                logdir=logdir,
                force_rerun=force_rerun,
                verbose=verbose,
            ))

    return pd.DataFrame(all_rows)


def _run_attack_matrix(
    pipeline,
    suite,
    attacks: Sequence[str],
    subject_col: str,
    subject_name: str,
    defense_name: str,
    user_task_ids: Sequence[str] | None,
    injection_task_ids: Sequence[str] | None,
    logdir: Path | None,
    force_rerun: bool,
    verbose: bool,
) -> list[dict]:
    """Run every attack against one already-built pipeline and flatten to rows.

    Shared by `evaluate_factories` (subject = optimizer) and `evaluate_agents`
    (subject = agent). `subject_col` names the identity column in the output.
    """
    rows: list[dict] = []
    from dspy_security_bench.attacks.adaptive import build_adaptive_attack, is_adaptive

    for attack_name in attacks:
        logger.info(
            f"  running {subject_col}={subject_name} × defense={defense_name} "
            f"× attack={attack_name}"
        )
        if is_adaptive(attack_name):
            # Defense-aware: the attack is crafted to defeat this cell's defense.
            attack = build_adaptive_attack(attack_name, defense_name, suite, pipeline)
        else:
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
        for r in _suite_results_to_rows(
            optimizer_name=subject_name,
            attack_name=attack_name,
            suite_results=suite_results,
            defense_name=defense_name,
        ):
            # Rename the identity column so agent runs read as `agent`, not
            # `optimizer`, while keeping the flatten helper generic.
            if subject_col != "optimizer":
                r[subject_col] = r.pop("optimizer")
            rows.append(r)
    return rows


def evaluate_agents(
    agents: dict,
    suite_name: str = "workspace",
    version: str = "v1",
    attacks: Sequence[str] = ("direct",),
    user_task_ids: Sequence[str] | None = None,
    injection_task_ids: Sequence[str] | None = None,
    logdir: Path | None = None,
    force_rerun: bool = True,
    verbose: bool = False,
    defenses: Sequence[str] = ("none",),
    pipeline_model_key: str = "gpt-4o-mini-2024-07-18",
) -> pd.DataFrame:
    """Benchmark generic `Agent` implementations (any framework) for
    prompt-injection robustness across the defense × attack matrix.

    The framework-agnostic sibling of `evaluate_factories`. Returns a flat
    DataFrame with an `agent` column (instead of `optimizer`), plus `defense`,
    `attack`, and per-task utility/security.

    Args:
        agents: mapping of display name → an object satisfying
            `dspy_security_bench.agents.Agent`.
        pipeline_model_key: a key present in agentdojo.models.MODEL_NAMES, used
            so the `important_instructions` attack can target consistently
            across agents (default: gpt-4o-mini's key, matching the rest of the
            benchmark). Change only if you know what the attack does with it.
    """
    from dspy_security_bench.adapters.generic import GenericAgentElement
    from dspy_security_bench.defenses import get_defense

    suite = get_suite(version, suite_name)
    all_rows: list[dict] = []

    for agent_name, agent in agents.items():
        for defense_name in defenses:
            defense = get_defense(defense_name)
            element = GenericAgentElement(agent=agent, defense=defense)
            pipeline = AgentPipeline([InitQuery(), element])
            pipeline.name = f"{pipeline_model_key}_generic_{_slug(agent_name)}_def-{defense_name}"
            all_rows.extend(_run_attack_matrix(
                pipeline=pipeline,
                suite=suite,
                attacks=attacks,
                subject_col="agent",
                subject_name=agent_name,
                defense_name=defense_name,
                user_task_ids=user_task_ids,
                injection_task_ids=injection_task_ids,
                logdir=logdir,
                force_rerun=force_rerun,
                verbose=verbose,
            ))

    return pd.DataFrame(all_rows)


def _slug(s: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    """Quick aggregation: utility + security rates per group.

    Groups by (optimizer, defense, attack) when a `defense` column is present
    (defense-benchmark runs), else by (optimizer, attack) for backward
    compatibility with pre-defenses result frames.
    """
    subject = "agent" if "agent" in df.columns else "optimizer"
    keys = [subject, "attack"]
    if "defense" in df.columns:
        keys = [subject, "defense", "attack"]
    grouped = df.groupby(keys).agg(
        utility_rate=("utility", "mean"),
        security_rate=("security", "mean"),
        injection_success_rate=("injection_succeeded", "mean"),
        n_runs=("utility", "size"),
    ).reset_index()
    return grouped
