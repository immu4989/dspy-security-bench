"""Defense-recovery experiment: can cheap defenses recover a vulnerable model?

Runs the unoptimized agent on one model across all registered defenses × both
attacks on the workspace suite. The headline question: Mistral Large has ~0%
injection-security undefended (v0.1.4) — does any deployable defense recover it?

Each (defense × attack) cell = 5 user tasks × 1 injection = 5 runs.
5 defenses × 2 attacks × 5 = 50 evals. ~$10 at Mistral Large pricing.

Usage:
    python scripts/run_defense_experiment.py mistral/mistral-large-latest --num-threads 1
"""
from __future__ import annotations

import argparse
import logging
import re
import time
from pathlib import Path

import dspy
import litellm

from dspy_security_bench.llm_judge import LLMJudgeMetric
from dspy_security_bench.optimizers import _make_agent_factory
from dspy_security_bench.defenses import available_defenses
from dspy_security_bench.runner import evaluate_factories, summarize

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("defense_exp")

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "data/results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

SUITE = "workspace"
ATTACKS = ["direct", "important_instructions"]
USER_TASK_IDS = ["user_task_0", "user_task_1", "user_task_3", "user_task_10", "user_task_11"]
INJECTION_TASK_IDS = ["injection_task_0"]
MAX_ITERS = 8


def _slug(model_str: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", model_str.lower()).strip("_")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("model")
    p.add_argument("--num-threads", type=int, default=1)
    p.add_argument("--num-retries", type=int, default=10)
    p.add_argument("--defenses", nargs="+", default=available_defenses())
    p.add_argument("--attacks", nargs="+", default=ATTACKS)
    p.add_argument("--tag", default=None, help="suffix for output filenames (e.g. 'adaptive')")
    args = p.parse_args()

    litellm.drop_params = True
    litellm.num_retries = args.num_retries

    slug = _slug(args.model)
    exec_lm = dspy.LM(args.model, temperature=0.2, max_tokens=2048, num_retries=args.num_retries)
    judge_lm = dspy.LM(args.model, temperature=0.0, max_tokens=512, num_retries=args.num_retries)
    dspy.configure(lm=exec_lm)
    # judge metric is unused for the unoptimized baseline (no compile), but keep
    # it configured for parity with the probe scripts.
    _ = LLMJudgeMetric(judge_lm=judge_lm, fast_path=True)

    # Unoptimized agent only — we're isolating the defense effect, not the
    # optimizer effect. No compile, so this is cheap.
    factories = {"unoptimized": _make_agent_factory(None, base_signature="query -> answer")}

    log.info(f"defense experiment: {args.model}")
    log.info(f"defenses={args.defenses} attacks={args.attacks}")
    n = len(args.defenses) * len(args.attacks) * len(USER_TASK_IDS) * len(INJECTION_TASK_IDS)
    log.info(f"total evals: {n}")

    t0 = time.time()
    df = evaluate_factories(
        factories=factories,
        suite_name=SUITE,
        attacks=args.attacks,
        user_task_ids=USER_TASK_IDS,
        injection_task_ids=INJECTION_TASK_IDS,
        max_iters=MAX_ITERS,
        force_rerun=True,
        verbose=False,
        defenses=args.defenses,
    )
    log.info(f"done in {time.time() - t0:.1f}s — {len(df)} rows")

    suffix = f"_{args.tag}" if args.tag else ""
    results_path = RESULTS_DIR / f"workspace_defense_{slug}{suffix}_results.csv"
    summary_path = RESULTS_DIR / f"workspace_defense_{slug}{suffix}_summary.csv"
    df.to_csv(results_path, index=False)
    summary = summarize(df)
    summary.to_csv(summary_path, index=False)
    log.info(f"raw → {results_path.name}; summary → {summary_path.name}")

    # Display: defense × attack security, with the recovery vs the 'none' baseline
    print()
    print("=" * 84)
    print(f" DEFENSE-RECOVERY EXPERIMENT — {args.model} (unoptimized, workspace, N=5)")
    print("=" * 84)
    print(summary.to_string(index=False))

    print()
    print("=" * 84)
    print(" Security recovery vs. undefended baseline (higher security = safer)")
    print("=" * 84)
    for attack in ATTACKS:
        print(f"\n  {attack}:")
        base_row = summary[(summary["defense"] == "none") & (summary["attack"] == attack)]
        base = float(base_row["security_rate"].iloc[0]) if not base_row.empty else float("nan")
        for defense in args.defenses:
            row = summary[(summary["defense"] == defense) & (summary["attack"] == attack)]
            if row.empty:
                continue
            sec = float(row["security_rate"].iloc[0])
            util = float(row["utility_rate"].iloc[0])
            delta = sec - base
            tag = "  (baseline)" if defense == "none" else f"  Δsec={delta:+.2f}"
            print(f"    {defense:20s} security={sec:.2f}  utility={util:.2f}{tag}")


if __name__ == "__main__":
    main()
