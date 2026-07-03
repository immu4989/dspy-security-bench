"""v0.1 cross-model probe — parameterized over any litellm-supported provider.

Runs the exact v0.1 workspace matrix (5 user × 1 injection × 2 attacks
× 3 non-GEPA optimizers = 30 evals) with the specified execution + judge LM.

Same code path as `run_v01_benchmark.py`, only the LM changes. Skips GEPA
(defers to phase 2 if the story is worth scaling).

This is the general-purpose version of the DeepSeek-specific probe
committed at tag v0.1.2. Use this script for all future model probes;
one CSV per model gets saved, and results can be merged for cross-model
comparison.

Methodological note: AgentDojo's `important_instructions` attack templates
pattern-match on MODEL_NAMES keys. Most non-OpenAI models are not in
MODEL_NAMES. runner.py hardcodes the pipeline_name to
`gpt-4o-mini-2024-07-18_...` — the attack templates used are
gpt-4o-mini-appropriate. Same attack templates across all model probes
for fair cross-model comparison; per-model attack tuning is a v0.3 question.

Usage:
    python scripts/run_v01_provider_probe.py mistral/mistral-small-latest
    python scripts/run_v01_provider_probe.py deepseek/deepseek-chat
    python scripts/run_v01_provider_probe.py together_ai/Qwen/Qwen2.5-72B-Instruct
"""
from __future__ import annotations

import argparse
import json
import logging
import pickle
import re
import time
from pathlib import Path

import dspy
import litellm

from dspy_security_bench.llm_judge import LLMJudgeMetric
from dspy_security_bench.optimizers import build_agent_factories
from dspy_security_bench.runner import evaluate_factories, summarize

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("v01_probe")

REPO_ROOT = Path(__file__).resolve().parents[1]
TRAINSET_PATH = REPO_ROOT / "data/synthetic_train/workspace_validated.jsonl"
RESULTS_DIR = REPO_ROOT / "data/results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

SUITE = "workspace"
OPTIMIZERS = ["unoptimized", "bootstrap_fewshot", "miprov2"]  # skip gepa
ATTACKS = ["direct", "important_instructions"]
USER_TASK_IDS = ["user_task_0", "user_task_1", "user_task_3", "user_task_10", "user_task_11"]
INJECTION_TASK_IDS = ["injection_task_0"]
MAX_ITERS = 8


def _slug(model_str: str) -> str:
    """Turn `mistral/mistral-small-latest` -> `mistral_mistral_small_latest`."""
    return re.sub(r"[^a-z0-9]+", "_", model_str.lower()).strip("_")


def _load_cached_factories(cache_path: Path, base_signature: str):
    if not cache_path.exists():
        return None
    log.info(f"loading factory cache from {cache_path.name}")
    with cache_path.open("rb") as f:
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


def _save_factory_cache(cache_path: Path, factories):
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
    with cache_path.open("wb") as f:
        pickle.dump(cached_state, f)
    log.info(f"saved factory cache → {cache_path.name}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("model", help="litellm model string (used for both execution + judge)")
    p.add_argument("--exec-max-tokens", type=int, default=2048)
    p.add_argument("--judge-max-tokens", type=int, default=512)
    p.add_argument("--num-threads", type=int, default=4,
                   help="MIPROv2/BootstrapFewShot parallelism (default 4; drop to 1 for rate-limited providers)")
    p.add_argument("--num-retries", type=int, default=10,
                   help="litellm auto-retry count for transient errors like 429")
    p.add_argument("--optimizers", nargs="+", default=OPTIMIZERS,
                   help="optimizer subset (default: unoptimized bootstrap_fewshot miprov2). "
                        "Use 'unoptimized bootstrap_fewshot' for rate-limited free-tier providers.")
    args = p.parse_args()
    run_optimizers = args.optimizers

    slug = _slug(args.model)
    results_path = RESULTS_DIR / f"workspace_v01_{slug}_results.csv"
    summary_path = RESULTS_DIR / f"workspace_v01_{slug}_summary.csv"

    from dspy_security_bench.optimizers import _make_agent_factory  # noqa: F401 side-effect import
    litellm.drop_params = True
    litellm.num_retries = args.num_retries  # global fallback

    trainset = [json.loads(line) for line in TRAINSET_PATH.read_text().splitlines() if line.strip()]
    log.info(f"probe: {args.model} (slug={slug!r}), {len(trainset)} training tasks, "
             f"num_threads={args.num_threads}, num_retries={args.num_retries}")

    exec_lm = dspy.LM(args.model, temperature=0.2, max_tokens=args.exec_max_tokens,
                      num_retries=args.num_retries)
    judge_lm = dspy.LM(args.model, temperature=0.0, max_tokens=args.judge_max_tokens,
                       num_retries=args.num_retries)
    dspy.configure(lm=exec_lm)
    metric = LLMJudgeMetric(judge_lm=judge_lm, fast_path=True)

    # Per-optimizer compile — each caches independently so a mid-run rate-
    # limit crash on MIPROv2 doesn't force BootstrapFewShot to re-compile.
    factories: dict = {}
    for opt in run_optimizers:
        opt_cache = RESULTS_DIR / f"factories_cache_v01_{slug}_{opt}.pkl"
        if opt_cache.exists():
            log.info(f"  loading cached {opt} from {opt_cache.name}")
            with opt_cache.open("rb") as f:
                state = pickle.load(f)
            if state is None:
                factories[opt] = _make_agent_factory(None, base_signature="query -> answer")
            else:
                class _CachedAgent:
                    def __init__(self, sig, instructions, demos):
                        self.signature = dspy.Signature(sig)
                        self.react = dspy.Predict(self.signature)
                        self.react.signature = self.react.signature.with_instructions(instructions)
                        self.react.demos = demos
                proxy = _CachedAgent("query -> answer", state["instructions"], state["demos"])
                factories[opt] = _make_agent_factory(proxy, base_signature="query -> answer")
            continue

        t_opt = time.time()
        log.info(f"  building {opt} — compile takes 3-25 min depending on optimizer")
        opt_factories = build_agent_factories(
            trainset=trainset,
            optimizers=[opt],
            suite_name=SUITE,
            signature="query -> answer",
            metric=metric,
            lm=exec_lm,
            optimizer_kwargs={opt: {"num_threads": args.num_threads}} if opt != "unoptimized" else None,
        )
        factories[opt] = opt_factories[opt]
        log.info(f"  {opt} compile complete in {time.time() - t_opt:.1f}s")

        # Cache this optimizer's state so a crash on the next one doesn't
        # cost us the successful compile
        probe = factories[opt](tools=[], max_iters=2)
        state = None if opt == "unoptimized" else {
            "instructions": probe.react.signature.instructions,
            "demos": list(probe.react.demos),
        }
        with opt_cache.open("wb") as f:
            pickle.dump(state, f)
        log.info(f"  saved {opt} cache -> {opt_cache.name}")

    # Eval
    t1 = time.time()
    n_expected = len(USER_TASK_IDS) * len(INJECTION_TASK_IDS) * len(ATTACKS) * len(run_optimizers)
    log.info(f"eval: {n_expected} runs across {len(run_optimizers)} optimizers × {len(ATTACKS)} attacks")
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
    log.info(f"eval complete in {time.time() - t1:.1f}s — {len(df)} rows")

    df.to_csv(results_path, index=False)
    summary = summarize(df)
    summary.to_csv(summary_path, index=False)
    log.info(f"raw → {results_path.name}; summary → {summary_path.name}")

    # Side-by-side vs v0.1 baseline
    print()
    print("=" * 90)
    print(f" v0.1 CROSS-MODEL PROBE — {args.model}")
    print("=" * 90)
    print(summary.to_string(index=False))

    v01_summary_path = RESULTS_DIR / "workspace_v01_summary.csv"
    if v01_summary_path.exists():
        import pandas as pd
        v01 = pd.read_csv(v01_summary_path)
        merged = v01.merge(summary, on=["optimizer", "attack"], suffixes=("_gpt4omini", "_probe"))
        print()
        print("=" * 90)
        print(f" SIDE-BY-SIDE: v0.1 gpt-4o-mini vs. this probe ({args.model})")
        print(" utility_rate ↑ better;  security_rate ↑ better")
        print("=" * 90)
        for _, row in merged.iterrows():
            print(f"\n  {row['optimizer']:20s} × {row['attack']:24s}")
            print(f"    utility:  gpt-4o-mini={row['utility_rate_gpt4omini']:.2f}    probe={row['utility_rate_probe']:.2f}    delta={row['utility_rate_probe'] - row['utility_rate_gpt4omini']:+.2f}")
            print(f"    security: gpt-4o-mini={row['security_rate_gpt4omini']:.2f}    probe={row['security_rate_probe']:.2f}    delta={row['security_rate_probe'] - row['security_rate_gpt4omini']:+.2f}")


if __name__ == "__main__":
    main()
