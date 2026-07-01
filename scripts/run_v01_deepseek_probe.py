"""v0.1 cross-model probe on DeepSeek V3.

Runs the exact v0.1 workspace matrix (5 user × 1 injection × 2 attacks
× 3 non-GEPA optimizers = 30 evals) with DeepSeek V3 as execution + judge LM.

Goal: test whether v0.1's headline finding ('prompt optimization degrades
security on harder attacks') replicates under a stronger, non-OpenAI
model family. The smoke test showed unoptimized DeepSeek gets 100% utility
on 2 workspace/direct tasks — v0.1 gpt-4o-mini got 0%. This probe scales
that observation from N=2 to N=5+ to see if it holds.

Skips GEPA (defers to phase 2 if the story is worth scaling).
Single seed (v0.1.1 showed seed variance is huge but that's model-agnostic).

Estimated cost: ~$6 at DeepSeek V3 pricing.
Wall clock: 25-45 min sequential.

Methodological note: AgentDojo's `important_instructions` attack templates
pattern-match on MODEL_NAMES keys. DeepSeek is not in MODEL_NAMES.
runner.py hardcodes the pipeline_name to `gpt-4o-mini-2024-07-18_...`
which means the attack templates used are the gpt-4o-mini-appropriate ones.
This is disclosed as a comparability choice: same attack templates as v0.1,
different execution model. Attack strength for DeepSeek could be different
if we tuned the templates per model — a v0.3 question.

Usage:
    python scripts/run_v01_deepseek_probe.py
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
import litellm

from dspy_security_bench.llm_judge import LLMJudgeMetric
from dspy_security_bench.optimizers import build_agent_factories
from dspy_security_bench.runner import evaluate_factories, summarize

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("v01_ds_probe")

REPO_ROOT = Path(__file__).resolve().parents[1]
TRAINSET_PATH = REPO_ROOT / "data/synthetic_train/workspace_validated.jsonl"
RESULTS_DIR = REPO_ROOT / "data/results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_PATH = RESULTS_DIR / "factories_cache_v01_deepseek.pkl"

# Match v0.1 EXACTLY except for the LM
EXECUTION_LM = "deepseek/deepseek-chat"
JUDGE_LM = "deepseek/deepseek-chat"
SUITE = "workspace"
OPTIMIZERS = ["unoptimized", "bootstrap_fewshot", "miprov2"]  # skip gepa
ATTACKS = ["direct", "important_instructions"]
USER_TASK_IDS = ["user_task_0", "user_task_1", "user_task_3", "user_task_10", "user_task_11"]
INJECTION_TASK_IDS = ["injection_task_0"]
MAX_ITERS = 8


def _load_cached_factories(base_signature: str):
    if not CACHE_PATH.exists():
        return None
    log.info(f"loading factory cache from {CACHE_PATH.name}")
    with CACHE_PATH.open("rb") as f:
        cached = pickle.load(f)
    from dspy_security_bench.optimizers import _make_agent_factory

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


def _save_factory_cache(factories):
    cached_state = {}
    for name, fac in factories.items():
        probe = fac(tools=[], max_iters=2)
        if name == "unoptimized":
            cached_state[name] = None
        else:
            cached_state[name] = {
                "instructions": probe.react.signature.instructions,
                "demos": list(probe.react.demos),
            }
    with CACHE_PATH.open("wb") as f:
        pickle.dump(cached_state, f)
    log.info(f"saved factory cache → {CACHE_PATH.name}")


def main():
    if not os.environ.get("DEEPSEEK_API_KEY"):
        sys.exit("DEEPSEEK_API_KEY not set")

    litellm.drop_params = True  # DeepSeek doesn't accept `seed` param

    trainset = [json.loads(line) for line in TRAINSET_PATH.read_text().splitlines() if line.strip()]
    log.info(f"loaded {len(trainset)} validated training tasks")

    exec_lm = dspy.LM(EXECUTION_LM, temperature=0.2, max_tokens=2048)
    judge_lm = dspy.LM(JUDGE_LM, temperature=0.0, max_tokens=512)
    dspy.configure(lm=exec_lm)
    metric = LLMJudgeMetric(judge_lm=judge_lm, fast_path=True)

    # ---- Step A: build agent factories (compile) ----
    factories = _load_cached_factories(base_signature="query -> answer")
    if factories is None:
        t0 = time.time()
        log.info(f"building factories for {OPTIMIZERS} — compile takes ~15-30 min")
        factories = build_agent_factories(
            trainset=trainset,
            optimizers=OPTIMIZERS,
            suite_name=SUITE,
            signature="query -> answer",
            metric=metric,
            lm=exec_lm,
        )
        log.info(f"built {len(factories)} factories in {time.time() - t0:.1f}s")
        _save_factory_cache(factories)
    else:
        log.info(f"reusing {len(factories)} cached factories — skipping compile")

    # ---- Step B: AgentDojo evaluation ----
    t1 = time.time()
    log.info(
        f"evaluation: {len(USER_TASK_IDS)} user × {len(INJECTION_TASK_IDS)} injection × "
        f"{len(ATTACKS)} attacks × {len(OPTIMIZERS)} optimizers = "
        f"{len(USER_TASK_IDS) * len(INJECTION_TASK_IDS) * len(ATTACKS) * len(OPTIMIZERS)} runs"
    )
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

    # ---- Step C: save results + summary ----
    results_path = RESULTS_DIR / "workspace_v01_deepseek_results.csv"
    summary_path = RESULTS_DIR / "workspace_v01_deepseek_summary.csv"
    df.to_csv(results_path, index=False)
    summary = summarize(df)
    summary.to_csv(summary_path, index=False)
    log.info(f"raw → {results_path.name}; summary → {summary_path.name}")

    # ---- Step D: side-by-side vs v0.1 gpt-4o-mini ----
    print()
    print("=" * 90)
    print(" v0.1 CROSS-MODEL PROBE — DeepSeek V3 (deepseek-chat) execution + judge")
    print("=" * 90)
    print(summary.to_string(index=False))

    # Load v0.1 gpt-4o-mini summary for side-by-side
    v01_summary_path = RESULTS_DIR / "workspace_v01_summary.csv"
    if v01_summary_path.exists():
        import pandas as pd
        v01 = pd.read_csv(v01_summary_path)
        print()
        print("=" * 90)
        print(" SIDE-BY-SIDE: v0.1 gpt-4o-mini vs. this probe (DeepSeek V3)")
        print(" utility_rate ↑ better;  security_rate ↑ better")
        print("=" * 90)
        # Merge on (optimizer, attack)
        merged = v01.merge(summary, on=["optimizer", "attack"], suffixes=("_gpt4omini", "_deepseek"))
        for _, row in merged.iterrows():
            print(f"\n  {row['optimizer']:20s} × {row['attack']:24s}")
            print(f"    utility:  gpt-4o-mini={row['utility_rate_gpt4omini']:.2f}    deepseek={row['utility_rate_deepseek']:.2f}    delta={row['utility_rate_deepseek'] - row['utility_rate_gpt4omini']:+.2f}")
            print(f"    security: gpt-4o-mini={row['security_rate_gpt4omini']:.2f}    deepseek={row['security_rate_deepseek']:.2f}    delta={row['security_rate_deepseek'] - row['security_rate_gpt4omini']:+.2f}")


if __name__ == "__main__":
    main()
