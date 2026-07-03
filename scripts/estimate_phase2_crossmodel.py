"""Phase 2 cross-model cost estimator.

Phase 2 is now a model-family sensitivity study (per v0.1.2 / v0.1.3): run the
same suite × attack × optimizer × task matrix across N model families and see
how the utility/security tradeoff shifts. This script sums per-model costs
using the same COST_MODEL as estimate_cost.py.

Each model runs as its own execution+judge+reflection (self-judged, matching
how the v0.1.x probes were run — same model executes and judges so there's no
cross-model judge confound within a single model's column).

Usage:
    python scripts/estimate_phase2_crossmodel.py
    python scripts/estimate_phase2_crossmodel.py --user-tasks 10 --seeds 2
"""
from __future__ import annotations

import argparse

from estimate_cost import Config, build_stages, _stage_cost_usd, PRICES


# Candidate model roster, ordered weak -> strong by observed v0.1.x unopt utility.
# gpt-4o-mini has NO synthesis cost (trainsets already built for it in v0.1);
# every other model reuses the SAME trainsets (tasks are model-agnostic), so
# synthesis is a one-time cost, not per-model. We attribute synthesis to the
# roster as a whole, below.
ROSTER = {
    "gpt-4o-mini":   "openai/gpt-4o-mini",
    "mistral-small": "mistral/mistral-small-latest",
    "deepseek-v3":   "deepseek/deepseek-chat",
    # candidates for the 5-model scope (need keys):
    "qwen-2.5-72b":  "deepinfra/Qwen/Qwen2.5-72B-Instruct",   # ~$0.35/$0.40
    "glm-4-plus":    "zhipuai/glm-4-plus",                     # ~$0.71/$0.71
}

# Prices for candidate models not already in estimate_cost.PRICES.
EXTRA_PRICES = {
    "deepinfra/Qwen/Qwen2.5-72B-Instruct": {"in": 0.35, "out": 0.40},
    "zhipuai/glm-4-plus":                  {"in": 0.71, "out": 0.71},
}

SCOPES = {
    "2-model": ["gpt-4o-mini", "deepseek-v3"],
    "3-model": ["gpt-4o-mini", "mistral-small", "deepseek-v3"],
    "5-model": ["gpt-4o-mini", "mistral-small", "deepseek-v3", "qwen-2.5-72b", "glm-4-plus"],
}


def _model_config(model_str: str, args, is_first: bool) -> Config:
    """One model's full phase-2 config. synthesis only on the first model
    (trainsets are shared across all models)."""
    return Config(
        suites=["workspace", "banking", "travel", "slack"],
        attacks=["direct", "important_instructions", "tool_knowledge", "ignore_previous"],
        optimizers=["unoptimized", "bootstrap_fewshot", "miprov2", "gepa"],
        user_tasks_per_suite=args.user_tasks,
        injection_tasks_per_suite=args.injection_tasks,
        seeds=args.seeds,
        synthesis_tasks_per_suite=200 if is_first else 0,
        exec_model=model_str,
        judge_model=model_str,       # self-judge, matches v0.1.x probe methodology
        reflection_model=model_str,  # GEPA reflection uses same model
        skip_synthesis=not is_first,
    )


def _model_cost(model_str: str, args, is_first: bool) -> tuple[float, int]:
    cfg = _model_config(model_str, args, is_first)
    stages = build_stages(cfg)
    cost = sum(_stage_cost_usd(s, cfg) for s in stages)
    calls = sum(s.calls for s in stages)
    return cost, calls


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--user-tasks", type=int, default=20)
    p.add_argument("--injection-tasks", type=int, default=4)
    p.add_argument("--seeds", type=int, default=3)
    args = p.parse_args()

    # Register extra prices so _stage_cost_usd can find them
    PRICES.update(EXTRA_PRICES)

    print()
    print("=" * 78)
    print(" PHASE 2 CROSS-MODEL COST ESTIMATE (DRY RUN)")
    print(f" scope per model: 4 suites × 4 attacks × 4 optimizers × "
          f"{args.user_tasks} user × {args.injection_tasks} inj × {args.seeds} seeds")
    print("=" * 78)

    # Per-model cost (each model treated as if it were first = includes its own
    # synthesis) — but synthesis is shared, so we compute it once and show the
    # marginal per-model cost separately.
    print()
    print(f" {'model':<16} {'exec price (in/out)':<22} {'per-model $':>12} {'calls':>10}")
    print(" " + "-" * 74)
    per_model = {}
    for label, model_str in ROSTER.items():
        price = {**PRICES, **EXTRA_PRICES}.get(model_str, {"in": 0, "out": 0})
        cost, calls = _model_cost(model_str, args, is_first=False)  # exclude synthesis
        per_model[label] = cost
        price_str = f"${price['in']}/{price['out']}"
        print(f" {label:<16} {price_str:<22} {cost:>11.2f} {calls:>10,}")

    # Synthesis is one-time (shared trainsets). Compute it once.
    synth_cfg = _model_config("openai/gpt-4o-mini", args, is_first=True)
    synth_stages = [s for s in build_stages(synth_cfg) if s.name.startswith("synthesis")]
    synth_cost = sum(_stage_cost_usd(s, synth_cfg) for s in synth_stages)
    print(" " + "-" * 74)
    print(f" {'(shared synthesis, one-time — 3 new suites)':<40} {synth_cost:>11.2f}")

    print()
    print("=" * 78)
    print(" SCOPE TOTALS")
    print("=" * 78)
    print(f" {'scope':<10} {'models':<44} {'total $':>12}")
    print(" " + "-" * 74)
    for scope_name, model_labels in SCOPES.items():
        total = synth_cost + sum(per_model[m] for m in model_labels)
        models_str = ", ".join(model_labels)
        if len(models_str) > 42:
            models_str = models_str[:39] + "..."
        print(f" {scope_name:<10} {models_str:<44} {total:>11.2f}")

    print()
    print(" Notes:")
    print("   - Synthesis ($) is one-time; trainsets are model-agnostic and shared.")
    print("   - Each model self-judges (exec == judge), matching v0.1.x probe methodology.")
    print("   - GEPA compile dominates every model's cost (~45%). Dropping GEPA")
    print("     cuts each model by roughly that fraction.")
    print("   - Qwen/GLM prices are estimates; verify against provider before committing.")
    print("   - Rate limits (esp. Mistral free tier, GLM) will extend wall-clock, not $.")


if __name__ == "__main__":
    main()
