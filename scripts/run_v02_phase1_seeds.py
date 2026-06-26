"""v0.2 phase 1 — seed sanity check.

Re-runs MIPROv2 + GEPA compiles with two additional seeds (1, 2) and
re-evaluates. BootstrapFewShot is deterministic given a trainset, so we
re-use the existing seed=0 result without re-compiling.

Combines with the existing phase 1 (seed=0) result to report
mean ± stddev per (optimizer, attack) cell. Decides whether the GEPA
underperformance from phase 1 was a single-seed fluke.

Cost: ~$10-15, wall-clock: ~50-70 min sequential.

Usage:
    python scripts/run_v02_phase1_seeds.py
"""
from __future__ import annotations

import json
import logging
import os
import pickle
import sys
import time
from pathlib import Path

import dspy
import pandas as pd

from dspy_security_bench.llm_judge import LLMJudgeMetric
from dspy_security_bench.optimizers import (
    _OPTIMIZER_FNS,
    _make_agent_factory,
    _tasks_to_dspy_examples,
    substring_match_metric,
)
from dspy_security_bench.adapters.agentdojo import make_reactv2_picklable
from dspy_security_bench.runner import evaluate_factories, summarize
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("v02_p1_seeds")

REPO_ROOT = Path(__file__).resolve().parents[1]
TRAINSET_PATH = REPO_ROOT / "data/synthetic_train/workspace_validated.jsonl"
V01_CACHE_PATH = REPO_ROOT / "data/results/factories_cache.pkl"  # has bootstrap_fewshot
RESULTS_DIR = REPO_ROOT / "data/results"
SEED0_RESULTS = RESULTS_DIR / "workspace_v02_phase1_results.csv"

EXECUTION_LM = "openai/gpt-4o-mini"
JUDGE_LM = "openai/gpt-4o-mini"
REFLECTION_LM = "openai/gpt-4o-mini"

SUITE = "workspace"
SEEDS = [1, 2]  # seed=0 already done; only re-do stochastic optimizers for new seeds
STOCHASTIC = ["miprov2", "gepa"]
ATTACKS = ["direct", "important_instructions"]
USER_TASK_IDS = ["user_task_0", "user_task_1", "user_task_3", "user_task_10", "user_task_11"]
INJECTION_TASK_IDS = ["injection_task_0"]
MAX_ITERS = 8


def _build_training_tools_local():
    """Match v0.1 train-time tool setup so we're truly re-running the same thing."""
    from dspy_security_bench.adapters.agentdojo import _make_dspy_tool
    suite = get_suite("v1", SUITE)
    runtime = FunctionsRuntime(functions=suite.tools)
    env = suite.load_and_inject_default_environment({})
    return [_make_dspy_tool(fn, runtime, env) for fn in runtime.functions.values()]


def _compile_single_optimizer(opt_name: str, seed: int, trainset_examples, metric, lm,
                              reflection_lm, base_signature: str = "query -> answer"):
    """Compile one optimizer with a specific seed, return its agent factory."""
    train_tools = _build_training_tools_local()
    student = dspy.ReActV2(signature=base_signature, tools=train_tools, max_iters=MAX_ITERS)
    make_reactv2_picklable(student)

    fn = _OPTIMIZER_FNS[opt_name]
    kwargs = {"auto": "light", "seed": seed}
    if opt_name == "gepa":
        kwargs["reflection_lm"] = reflection_lm

    log.info(f"  compiling {opt_name} (seed={seed}) — this is the costly step")
    t0 = time.time()
    with dspy.context(lm=lm):
        compiled = fn(student=student, trainset=trainset_examples, metric=metric, **kwargs)
    log.info(f"  {opt_name} (seed={seed}) compile complete in {time.time() - t0:.1f}s")
    return _make_agent_factory(compiled, base_signature=base_signature)


def _bootstrap_factory_from_v01_cache(base_signature: str = "query -> answer"):
    """Reload bootstrap_fewshot from v0.1 cache (deterministic — same across seeds)."""
    with V01_CACHE_PATH.open("rb") as f:
        cached = pickle.load(f)
    state = cached["bootstrap_fewshot"]

    class _CachedAgent:
        def __init__(self, sig, instructions, demos):
            self.signature = dspy.Signature(sig)
            self.react = dspy.Predict(self.signature)
            self.react.signature = self.react.signature.with_instructions(instructions)
            self.react.demos = demos

    proxy = _CachedAgent(base_signature, state["instructions"], state["demos"])
    return _make_agent_factory(proxy, base_signature=base_signature)


def _unoptimized_factory():
    return _make_agent_factory(None, base_signature="query -> answer")


def main():
    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY not set")
    if not SEED0_RESULTS.exists():
        sys.exit(f"seed=0 results not found at {SEED0_RESULTS} — run scripts/run_v02_phase1.py first")

    # Load trainset
    raw_tasks = [json.loads(line) for line in TRAINSET_PATH.read_text().splitlines() if line.strip()]
    trainset_examples = _tasks_to_dspy_examples(raw_tasks, input_field="query")
    log.info(f"loaded {len(trainset_examples)} training examples")

    # LMs
    exec_lm = dspy.LM(EXECUTION_LM, temperature=0.2)
    judge_lm = dspy.LM(JUDGE_LM, temperature=0.0)
    reflection_lm = dspy.LM(REFLECTION_LM, temperature=0.7)
    dspy.configure(lm=exec_lm)
    metric = LLMJudgeMetric(judge_lm=judge_lm, fast_path=True)

    # Shared deterministic factories (no seed dependence)
    shared_factories = {
        "unoptimized": _unoptimized_factory(),
        "bootstrap_fewshot": _bootstrap_factory_from_v01_cache(),
    }

    # Per-seed: compile stochastic optimizers + evaluate
    new_results_dfs = []
    for seed in SEEDS:
        log.info(f"\n=== seed={seed} ===")
        per_seed_factories = dict(shared_factories)
        for opt_name in STOCHASTIC:
            cache_path = RESULTS_DIR / f"factories_cache_v02_p1_seed{seed}_{opt_name}.pkl"
            if cache_path.exists():
                log.info(f"  using cached {opt_name} (seed={seed}) from {cache_path.name}")
                with cache_path.open("rb") as f:
                    state = pickle.load(f)

                class _CachedAgent:
                    def __init__(self, sig, instructions, demos):
                        self.signature = dspy.Signature(sig)
                        self.react = dspy.Predict(self.signature)
                        self.react.signature = self.react.signature.with_instructions(instructions)
                        self.react.demos = demos
                proxy = _CachedAgent("query -> answer", state["instructions"], state["demos"])
                per_seed_factories[opt_name] = _make_agent_factory(proxy, base_signature="query -> answer")
            else:
                per_seed_factories[opt_name] = _compile_single_optimizer(
                    opt_name, seed, trainset_examples, metric, exec_lm, reflection_lm,
                )
                probe = per_seed_factories[opt_name](tools=[], max_iters=2)
                with cache_path.open("wb") as f:
                    pickle.dump({
                        "instructions": probe.react.signature.instructions,
                        "demos": list(probe.react.demos),
                    }, f)
                log.info(f"  saved {opt_name} (seed={seed}) cache → {cache_path.name}")

        log.info(f"  evaluating seed={seed} across {len(per_seed_factories)} optimizers × {len(ATTACKS)} attacks")
        df = evaluate_factories(
            factories=per_seed_factories,
            suite_name=SUITE,
            attacks=ATTACKS,
            user_task_ids=USER_TASK_IDS,
            injection_task_ids=INJECTION_TASK_IDS,
            max_iters=MAX_ITERS,
            force_rerun=True,
            verbose=False,
        )
        df["seed"] = seed
        new_results_dfs.append(df)
        per_seed_csv = RESULTS_DIR / f"workspace_v02_phase1_seed{seed}_results.csv"
        df.to_csv(per_seed_csv, index=False)
        log.info(f"  saved seed={seed} eval → {per_seed_csv.name}")

    # Load seed=0 + concat with new seeds
    seed0_df = pd.read_csv(SEED0_RESULTS)
    seed0_df["seed"] = 0
    all_df = pd.concat([seed0_df] + new_results_dfs, ignore_index=True)
    combined_path = RESULTS_DIR / "workspace_v02_phase1_seeds_all.csv"
    all_df.to_csv(combined_path, index=False)
    log.info(f"\ncombined results → {combined_path.name}")

    # Aggregate: mean ± std per (optimizer, attack)
    agg = all_df.groupby(["optimizer", "attack"]).agg(
        utility_mean=("utility", "mean"),
        utility_std=("utility", "std"),
        security_mean=("security", "mean"),
        security_std=("security", "std"),
        n_seeds=("seed", "nunique"),
        n_runs=("utility", "size"),
    ).reset_index()
    agg_path = RESULTS_DIR / "workspace_v02_phase1_seeds_summary.csv"
    agg.to_csv(agg_path, index=False)

    # Display
    print()
    print("=" * 90)
    print(f" v0.2 phase 1 seed sanity check — {len(SEEDS) + 1} seeds × {len(USER_TASK_IDS)} user × {len(INJECTION_TASK_IDS)} injection × {len(ATTACKS)} attacks")
    print("=" * 90)
    print(agg.to_string(index=False, float_format=lambda v: f"{v:.3f}" if pd.notna(v) else "—"))

    # Gate decision: does the phase 1 monotonic order hold?
    print()
    print("=" * 90)
    print(" Gate decision — does the optimizer-aggressiveness security ordering hold across seeds?")
    print("=" * 90)
    order = ["unoptimized", "bootstrap_fewshot", "miprov2", "gepa"]
    for attack in ATTACKS:
        print(f"\n  {attack} — security mean ± std (n_seeds for stochastic):")
        for opt in order:
            row = agg[(agg["optimizer"] == opt) & (agg["attack"] == attack)]
            if not row.empty:
                r = row.iloc[0]
                std_display = f"±{r['security_std']:.3f}" if pd.notna(r['security_std']) and r['n_seeds'] > 1 else "(1 seed)"
                print(f"    {opt:20s} {r['security_mean']:.3f} {std_display}  (n_seeds={int(r['n_seeds'])})")


if __name__ == "__main__":
    main()
