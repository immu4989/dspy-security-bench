"""v0.1 end-to-end benchmark run.

Loads the validated synthetic trainset, builds three agent factories
(unoptimized, BootstrapFewShot, MIPROv2 light), and runs them against a
small AgentDojo workspace + 2 attacks subset. Saves a results DataFrame
and a (optimizer × attack) summary.

Usage:
    python scripts/run_v01_benchmark.py
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
from dspy_security_bench.optimizers import build_agent_factories
from dspy_security_bench.runner import evaluate_factories, summarize

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("run_v01")

# ---------------------------------------------------------------------------
# Config — keep deliberately tight for the v0.1 first run
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
TRAINSET_PATH = REPO_ROOT / "data/synthetic_train/workspace_validated.jsonl"
RESULTS_DIR = REPO_ROOT / "data/results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Use gpt-4o-mini for everything — cheap, fast, good enough for v0.1
EXECUTION_LM = "openai/gpt-4o-mini"
JUDGE_LM = "openai/gpt-4o-mini"

SUITE = "workspace"
OPTIMIZERS = ["unoptimized", "bootstrap_fewshot", "miprov2"]
ATTACKS = ["direct", "important_instructions"]
USER_TASK_IDS = ["user_task_0", "user_task_1", "user_task_3", "user_task_10", "user_task_11"]
INJECTION_TASK_IDS = ["injection_task_0"]
MAX_ITERS = 8


def main():
    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY not set")

    # Load validated trainset
    trainset = [json.loads(line) for line in TRAINSET_PATH.read_text().splitlines() if line.strip()]
    log.info(f"loaded {len(trainset)} validated training tasks from {TRAINSET_PATH.name}")

    # Configure the execution + judge LM
    exec_lm = dspy.LM(EXECUTION_LM, temperature=0.2)
    judge_lm = dspy.LM(JUDGE_LM, temperature=0.0)
    dspy.configure(lm=exec_lm)
    metric = LLMJudgeMetric(judge_lm=judge_lm, fast_path=True)

    # ---- Step A: build agent factories (this is where optimization runs) ----
    # Cache the optimized state (instructions + demos) so a re-run after a
    # downstream crash doesn't repay the ~$5-8 optimization cost.
    cache_path = RESULTS_DIR / "factories_cache.pkl"
    factories = None
    if cache_path.exists():
        try:
            log.info(f"loading factory cache from {cache_path.name}")
            with cache_path.open("rb") as f:
                cached = pickle.load(f)
            # Rebuild factories from the cached (instructions, demos) pairs
            from dspy_security_bench.optimizers import _make_agent_factory
            from dspy.predict.react_v2 import ReActV2  # for type only

            class _CachedAgent:
                def __init__(self, sig, instructions, demos):
                    self.signature = dspy.Signature(sig)
                    self.react = dspy.Predict(self.signature)
                    self.react.signature = self.react.signature.with_instructions(instructions)
                    self.react.demos = demos

            factories = {}
            for name, state in cached.items():
                if state is None:
                    factories[name] = _make_agent_factory(None, base_signature="query -> answer")
                else:
                    proxy = _CachedAgent("query -> answer", state["instructions"], state["demos"])
                    factories[name] = _make_agent_factory(proxy, base_signature="query -> answer")
            log.info(f"loaded {len(factories)} cached factories — skipping optimization")
        except Exception as e:
            log.warning(f"factory cache load failed ({type(e).__name__}: {e}); will re-optimize")
            factories = None

    if factories is None:
        t0 = time.time()
        log.info(f"building factories for {OPTIMIZERS} — optimization can take 5-15 min")
        factories = build_agent_factories(
            trainset=trainset,
            optimizers=OPTIMIZERS,
            suite_name=SUITE,
            signature="query -> answer",
            metric=metric,
            lm=exec_lm,
        )
        log.info(f"built {len(factories)} factories in {time.time() - t0:.1f}s")

        # Save the optimized state to disk so re-runs are cheap
        cached_state = {}
        for name, fac in factories.items():
            # Build one agent to inspect what state was applied
            probe_agent = fac(tools=[], max_iters=2)
            if name == "unoptimized":
                cached_state[name] = None
            else:
                cached_state[name] = {
                    "instructions": probe_agent.react.signature.instructions,
                    "demos": list(probe_agent.react.demos),
                }
        with cache_path.open("wb") as f:
            pickle.dump(cached_state, f)
        log.info(f"saved factory cache → {cache_path.name}")

    # ---- Step B: AgentDojo evaluation ----
    t1 = time.time()
    log.info(f"running evaluation: {len(USER_TASK_IDS)} user × {len(INJECTION_TASK_IDS)} injection × {len(ATTACKS)} attacks × {len(OPTIMIZERS)} optimizers")
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

    # ---- Step C: save results ----
    results_path = RESULTS_DIR / "workspace_v01_results.csv"
    df.to_csv(results_path, index=False)
    log.info(f"raw results → {results_path}")

    summary = summarize(df)
    summary_path = RESULTS_DIR / "workspace_v01_summary.csv"
    summary.to_csv(summary_path, index=False)
    log.info(f"summary     → {summary_path}")

    print()
    print("=" * 80)
    print(" Raw results")
    print("=" * 80)
    print(df.to_string(index=False))
    print()
    print("=" * 80)
    print(" Summary (utility_rate ↑ better, security_rate ↑ better)")
    print("=" * 80)
    print(summary.to_string(index=False))


if __name__ == "__main__":
    main()
