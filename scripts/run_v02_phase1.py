"""v0.2 phase 1 — add GEPA to the optimizer comparison.

Runs only the *new* work: builds the GEPA factory, then re-runs the full
4-optimizer × 2-attack evaluation on the workspace suite (reusing the v0.1
cached factories for unoptimized / bootstrap_fewshot / miprov2).

Cheap by design — ~$3-6, ~15-25 min wall-clock — so we can decide whether
to commit to phase 2 at all before spending real money.

Usage:
    python scripts/run_v02_phase1.py
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

from dspy_security_bench.llm_judge import LLMJudgeMetric
from dspy_security_bench.optimizers import (
    _make_agent_factory,
    build_agent_factories,
)
from dspy_security_bench.runner import evaluate_factories, summarize

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("v02_phase1")

REPO_ROOT = Path(__file__).resolve().parents[1]
TRAINSET_PATH = REPO_ROOT / "data/synthetic_train/workspace_validated.jsonl"
V01_CACHE_PATH = REPO_ROOT / "data/results/factories_cache.pkl"
V02_CACHE_PATH = REPO_ROOT / "data/results/factories_cache_v02_phase1.pkl"
RESULTS_DIR = REPO_ROOT / "data/results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Same config as v0.1 — keep variables constant; only adding GEPA
EXECUTION_LM = "openai/gpt-4o-mini"
JUDGE_LM = "openai/gpt-4o-mini"
REFLECTION_LM = "openai/gpt-4o-mini"

SUITE = "workspace"
OPTIMIZERS = ["unoptimized", "bootstrap_fewshot", "miprov2", "gepa"]
ATTACKS = ["direct", "important_instructions"]
USER_TASK_IDS = ["user_task_0", "user_task_1", "user_task_3", "user_task_10", "user_task_11"]
INJECTION_TASK_IDS = ["injection_task_0"]
MAX_ITERS = 8


def _load_v01_factories(base_signature: str) -> dict:
    """Reconstruct the v0.1 factories from cache for the 3 existing optimizers."""
    if not V01_CACHE_PATH.exists():
        log.warning(f"v0.1 cache not found at {V01_CACHE_PATH} — will rebuild from scratch")
        return None
    with V01_CACHE_PATH.open("rb") as f:
        cached = pickle.load(f)
    log.info(f"loaded v0.1 cache with {len(cached)} optimizer states: {list(cached.keys())}")

    class _CachedAgent:
        def __init__(self, sig, instructions, demos):
            self.signature = dspy.Signature(sig)
            self.react = dspy.Predict(self.signature)
            self.react.signature = self.react.signature.with_instructions(instructions)
            self.react.demos = demos

    factories = {}
    for name, state in cached.items():
        if state is None:
            factories[name] = _make_agent_factory(None, base_signature=base_signature)
        else:
            proxy = _CachedAgent(base_signature, state["instructions"], state["demos"])
            factories[name] = _make_agent_factory(proxy, base_signature=base_signature)
    return factories


def main():
    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY not set")

    trainset = [json.loads(line) for line in TRAINSET_PATH.read_text().splitlines() if line.strip()]
    log.info(f"loaded {len(trainset)} validated training tasks")

    exec_lm = dspy.LM(EXECUTION_LM, temperature=0.2)
    judge_lm = dspy.LM(JUDGE_LM, temperature=0.0)
    reflection_lm = dspy.LM(REFLECTION_LM, temperature=0.7)
    dspy.configure(lm=exec_lm)
    metric = LLMJudgeMetric(judge_lm=judge_lm, fast_path=True)

    # ---- Step A: load v0.1 factories (no cost) ----
    factories = _load_v01_factories(base_signature="query -> answer")
    if factories is None:
        sys.exit("could not load v0.1 cache — run scripts/run_v01_benchmark.py first")

    # ---- Step B: add GEPA factory (new work) ----
    if V02_CACHE_PATH.exists():
        log.info(f"loading v0.2 phase 1 GEPA cache from {V02_CACHE_PATH.name}")
        with V02_CACHE_PATH.open("rb") as f:
            gepa_state = pickle.load(f)
        # Rebuild factory from cached GEPA state
        class _CachedAgent:
            def __init__(self, sig, instructions, demos):
                self.signature = dspy.Signature(sig)
                self.react = dspy.Predict(self.signature)
                self.react.signature = self.react.signature.with_instructions(instructions)
                self.react.demos = demos
        proxy = _CachedAgent("query -> answer", gepa_state["instructions"], gepa_state["demos"])
        factories["gepa"] = _make_agent_factory(proxy, base_signature="query -> answer")
        log.info("  loaded cached GEPA factory — skipping GEPA compile")
    else:
        t0 = time.time()
        log.info("building GEPA factory — this is the costly step (~$3-5, ~10-20 min)")
        gepa_factories = build_agent_factories(
            trainset=trainset,
            optimizers=["gepa"],
            suite_name=SUITE,
            signature="query -> answer",
            metric=metric,
            lm=exec_lm,
            optimizer_kwargs={"gepa": {"reflection_lm": reflection_lm, "auto": "light"}},
        )
        factories["gepa"] = gepa_factories["gepa"]
        log.info(f"  GEPA compile complete in {time.time() - t0:.1f}s")

        # Cache the GEPA state
        probe = factories["gepa"](tools=[], max_iters=2)
        with V02_CACHE_PATH.open("wb") as f:
            pickle.dump({
                "instructions": probe.react.signature.instructions,
                "demos": list(probe.react.demos),
            }, f)
        log.info(f"  saved GEPA cache → {V02_CACHE_PATH.name}")

    log.info(f"factories ready: {list(factories.keys())}")

    # ---- Step C: evaluation across all 4 optimizers ----
    t1 = time.time()
    log.info(f"evaluation: {len(USER_TASK_IDS)} user × {len(INJECTION_TASK_IDS)} injection × {len(ATTACKS)} attacks × {len(OPTIMIZERS)} optimizers = {len(USER_TASK_IDS) * len(INJECTION_TASK_IDS) * len(ATTACKS) * len(OPTIMIZERS)} runs")
    df = evaluate_factories(
        factories=factories,
        suite_name=SUITE,
        attacks=ATTACKS,
        user_task_ids=USER_TASK_IDS,
        injection_task_ids=INJECTION_TASK_IDS,
        max_iters=MAX_ITERS,
        force_rerun=True,
        verbose=False,
    )
    log.info(f"evaluation complete in {time.time() - t1:.1f}s — {len(df)} rows")

    # ---- Step D: save results ----
    results_path = RESULTS_DIR / "workspace_v02_phase1_results.csv"
    summary_path = RESULTS_DIR / "workspace_v02_phase1_summary.csv"
    df.to_csv(results_path, index=False)
    summary = summarize(df)
    summary.to_csv(summary_path, index=False)
    log.info(f"raw → {results_path.name}; summary → {summary_path.name}")

    print()
    print("=" * 80)
    print(" v0.2 phase 1 — full 4-optimizer summary")
    print("=" * 80)
    print(summary.to_string(index=False))
    print()
    # Gate decision helpers
    print("=" * 80)
    print(" Gate decision data — phase 1 → phase 2")
    print("=" * 80)
    grouped = summary.set_index(["optimizer", "attack"])
    for attack in ATTACKS:
        print(f"\n  {attack}:")
        for opt in OPTIMIZERS:
            try:
                row = grouped.loc[(opt, attack)]
                print(f"    {opt:20s} utility={row['utility_rate']:.2f}  security={row['security_rate']:.2f}")
            except KeyError:
                print(f"    {opt:20s} (no data)")


if __name__ == "__main__":
    main()
