"""Dry-run cost estimator for phase 2 (and any other configuration).

Walks the configured suite × attack × optimizer × task × seed matrix and
prints the expected LM-call volume, token volume, and dollar cost. Makes
zero LM calls. Use this BEFORE kicking off a paid run to confirm scope
and to catch scoping mistakes that would otherwise burn real money.

Per-stage cost model lives in the COST_MODEL dict below. Update it
when provider prices change or when you have better empirical numbers
from a real run.

Usage:
    # Default phase 2 config
    python scripts/estimate_cost.py

    # v0.1 single-seed workspace (sanity check the model against history)
    python scripts/estimate_cost.py --preset v0.1

    # Tight smoke test
    python scripts/estimate_cost.py --suites workspace --user-tasks 5 \
        --injection-tasks 1 --attacks direct --seeds 1 \
        --optimizers unoptimized bootstrap_fewshot

    # Custom: only the eval, skip synthesis + compile
    python scripts/estimate_cost.py --skip-synthesis --skip-compile
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Pricing as of 2026-06. USD per 1M tokens. Update when providers move.
# Source: https://openai.com/api/pricing/, https://anthropic.com/pricing
# ---------------------------------------------------------------------------
PRICES = {
    "openai/gpt-4o-mini":      {"in": 0.15, "out": 0.60},
    "openai/gpt-4o":           {"in": 2.50, "out": 10.00},
    "anthropic/claude-3-5-haiku": {"in": 0.80, "out": 4.00},
    "anthropic/claude-3-5-sonnet": {"in": 3.00, "out": 15.00},
}


# ---------------------------------------------------------------------------
# Per-stage LM-call model. Numbers are empirical estimates from the v0.1
# + v0.1.1 runs against the workspace suite at gpt-4o-mini. Re-tune when
# you have data for the other suites.
# ---------------------------------------------------------------------------
@dataclass
class StageCost:
    name: str
    calls: int
    avg_input_tokens: int
    avg_output_tokens: int
    model: str
    notes: str = ""


# Empirical: one ReActV2 agent-run with max_iters=8 does ~10 LM calls.
# Context grows iteration-over-iteration, so average input across the 10
# calls is ~5k tokens; average output is ~500 tokens (mostly tool args
# until the final answer).
LM_CALLS_PER_AGENT_RUN = 10
AGENT_RUN_AVG_INPUT = 5000
AGENT_RUN_AVG_OUTPUT = 500


def _agent_run_stage(name: str, n_agent_runs: int, model: str, notes: str = "") -> StageCost:
    return StageCost(
        name=name,
        calls=n_agent_runs * LM_CALLS_PER_AGENT_RUN,
        avg_input_tokens=AGENT_RUN_AVG_INPUT,
        avg_output_tokens=AGENT_RUN_AVG_OUTPUT,
        model=model,
        notes=notes,
    )


COST_MODEL = {
    # Synthesis: ~n raw tasks generated, ~50/50 split gpt-4o + claude-sonnet.
    # Each generation is a one-shot LM call (no agent loop).
    "synthesis_gpt4o": lambda n: StageCost(
        name=f"synthesis (gpt-4o, n={n // 2})",
        calls=n // 2, avg_input_tokens=2000, avg_output_tokens=600,
        model="openai/gpt-4o",
        notes="one call per generated task; system+few-shot prompt is heavy",
    ),
    "synthesis_claude": lambda n: StageCost(
        name=f"synthesis (claude-sonnet, n={n - n // 2})",
        calls=n - n // 2, avg_input_tokens=2000, avg_output_tokens=600,
        model="anthropic/claude-3-5-sonnet",
        notes="one call per generated task",
    ),
    # Compile: counted in AGENT-RUNS (each agent run = ~10 LM calls).
    # BootstrapFewShot: ~60 candidate trajectories total to find ~4 demos.
    "compile_bootstrap": lambda: _agent_run_stage(
        "compile BootstrapFewShot — agent runs (per seed × suite)",
        n_agent_runs=60, model="EXEC",
        notes="~60 candidate trajectories × ~10 LM calls per ReActV2 run",
    ),
    # MIPROv2 light: ~7 trials × ~30 minibatch evals per trial = 210 agent runs.
    # Plus prompt-generation overhead (~50 instruction-proposer calls, small).
    "compile_mipro_agent": lambda: _agent_run_stage(
        "compile MIPROv2 light — agent runs (per seed × suite)",
        n_agent_runs=210, model="EXEC",
        notes="auto='light' = ~7 trials × ~30 trainset evals each",
    ),
    "compile_mipro_proposer": lambda: StageCost(
        name="compile MIPROv2 light — instruction proposer (per seed × suite)",
        calls=50, avg_input_tokens=4000, avg_output_tokens=400,
        model="EXEC",
        notes="proposes candidate prompt phrasings; small fraction of total",
    ),
    # GEPA light: empirical 2h+ wall-clock at gpt-4o-mini.
    # ~1500 agent-runs across the reflective optimization loop, plus a smaller
    # number of reflection-LM calls.
    "compile_gepa_agent": lambda: _agent_run_stage(
        "compile GEPA light — agent runs (per seed × suite)",
        n_agent_runs=1500, model="EXEC",
        notes="reflective optimizer; agent runs dominate the cost",
    ),
    "compile_gepa_reflection": lambda: StageCost(
        name="compile GEPA light — reflection calls (per seed × suite)",
        calls=200, avg_input_tokens=8000, avg_output_tokens=1500,
        model="REFLECT",
        notes="reflection LM proposes new prompt phrasings (separate from exec)",
    ),
    # Eval: each cell-row is one agent-run + one judge call.
    "eval_agent": lambda n_evals: _agent_run_stage(
        f"evaluation — agent runs (n_evals={n_evals})",
        n_agent_runs=n_evals, model="EXEC",
        notes="one ReActV2 run per (user × injection × optimizer × attack × seed × suite)",
    ),
    "eval_judge": lambda n_evals: StageCost(
        name=f"evaluation — judge calls (n_evals={n_evals})",
        calls=n_evals, avg_input_tokens=1500, avg_output_tokens=80,
        model="JUDGE",
        notes="one LLM-as-judge call per eval (substring fast-path skips most)",
    ),
}


@dataclass
class Config:
    suites: list[str]
    attacks: list[str]
    optimizers: list[str]
    user_tasks_per_suite: int
    injection_tasks_per_suite: int
    seeds: int
    synthesis_tasks_per_suite: int
    exec_model: str
    judge_model: str
    reflection_model: str
    skip_synthesis: bool = False
    skip_compile: bool = False
    skip_eval: bool = False
    stages: list[StageCost] = field(default_factory=list)

    @property
    def n_evals(self) -> int:
        per_seed = (
            len(self.suites)
            * len(self.attacks)
            * len(self.optimizers)
            * self.user_tasks_per_suite
            * self.injection_tasks_per_suite
        )
        return per_seed * self.seeds

    @property
    def n_compiles(self) -> int:
        # Compile happens once per (suite × stochastic_optimizer × seed)
        # unoptimized is not compiled
        stochastic = [o for o in self.optimizers if o != "unoptimized"]
        return len(self.suites) * len(stochastic) * self.seeds


PRESETS = {
    "v0.1": dict(
        suites=["workspace"],
        attacks=["direct", "important_instructions"],
        optimizers=["unoptimized", "bootstrap_fewshot", "miprov2"],
        user_tasks_per_suite=5,
        injection_tasks_per_suite=1,
        seeds=1,
        synthesis_tasks_per_suite=200,
        exec_model="openai/gpt-4o-mini",
        judge_model="openai/gpt-4o-mini",
        reflection_model="openai/gpt-4o-mini",
    ),
    "v0.1.1": dict(
        suites=["workspace"],
        attacks=["direct", "important_instructions"],
        optimizers=["unoptimized", "bootstrap_fewshot", "miprov2", "gepa"],
        user_tasks_per_suite=5,
        injection_tasks_per_suite=1,
        seeds=3,
        synthesis_tasks_per_suite=0,  # trainset already built
        exec_model="openai/gpt-4o-mini",
        judge_model="openai/gpt-4o-mini",
        reflection_model="openai/gpt-4o-mini",
    ),
    "phase2": dict(
        suites=["workspace", "banking", "travel", "slack"],
        attacks=["direct", "important_instructions", "tool_knowledge", "ignore_previous"],
        optimizers=["unoptimized", "bootstrap_fewshot", "miprov2", "gepa"],
        user_tasks_per_suite=20,
        injection_tasks_per_suite=4,
        seeds=3,
        synthesis_tasks_per_suite=200,  # 3 new suites need fresh trainsets
        exec_model="openai/gpt-4o-mini",
        judge_model="anthropic/claude-3-5-haiku",
        reflection_model="openai/gpt-4o-mini",
    ),
}


# ---------------------------------------------------------------------------
# Cost math
# ---------------------------------------------------------------------------

def _resolve_model(name: str, cfg: Config) -> str:
    return {"EXEC": cfg.exec_model, "JUDGE": cfg.judge_model, "REFLECT": cfg.reflection_model}.get(name, name)


def _stage_cost_usd(stage: StageCost, cfg: Config) -> float:
    model = _resolve_model(stage.model, cfg)
    if model not in PRICES:
        raise ValueError(f"unknown model {model!r}; add it to PRICES")
    p = PRICES[model]
    in_cost = (stage.calls * stage.avg_input_tokens / 1_000_000) * p["in"]
    out_cost = (stage.calls * stage.avg_output_tokens / 1_000_000) * p["out"]
    return in_cost + out_cost


def build_stages(cfg: Config) -> list[StageCost]:
    stages = []

    # synthesis (per suite that doesn't already have a trainset)
    if not cfg.skip_synthesis and cfg.synthesis_tasks_per_suite > 0:
        new_suites = len([s for s in cfg.suites if not _trainset_exists(s)])
        if new_suites > 0:
            n_total = cfg.synthesis_tasks_per_suite * new_suites
            stages.append(COST_MODEL["synthesis_gpt4o"](n_total))
            stages.append(COST_MODEL["synthesis_claude"](n_total))

    # compile (per suite × stochastic optimizer × seed)
    if not cfg.skip_compile:
        n_per_optimizer = len(cfg.suites) * cfg.seeds
        if "bootstrap_fewshot" in cfg.optimizers:
            s = COST_MODEL["compile_bootstrap"]()
            stages.append(StageCost(
                name=s.name + f" × {n_per_optimizer} configs",
                calls=s.calls * n_per_optimizer,
                avg_input_tokens=s.avg_input_tokens,
                avg_output_tokens=s.avg_output_tokens,
                model=s.model, notes=s.notes,
            ))
        if "miprov2" in cfg.optimizers:
            for key in ("compile_mipro_agent", "compile_mipro_proposer"):
                s = COST_MODEL[key]()
                stages.append(StageCost(
                    name=s.name + f" × {n_per_optimizer} configs",
                    calls=s.calls * n_per_optimizer,
                    avg_input_tokens=s.avg_input_tokens,
                    avg_output_tokens=s.avg_output_tokens,
                    model=s.model, notes=s.notes,
                ))
        if "gepa" in cfg.optimizers:
            for key in ("compile_gepa_agent", "compile_gepa_reflection"):
                s = COST_MODEL[key]()
                stages.append(StageCost(
                    name=s.name + f" × {n_per_optimizer} configs",
                    calls=s.calls * n_per_optimizer,
                    avg_input_tokens=s.avg_input_tokens,
                    avg_output_tokens=s.avg_output_tokens,
                    model=s.model, notes=s.notes,
                ))

    # eval
    if not cfg.skip_eval and cfg.n_evals > 0:
        stages.append(COST_MODEL["eval_agent"](cfg.n_evals))
        stages.append(COST_MODEL["eval_judge"](cfg.n_evals))

    return stages


def _trainset_exists(suite: str) -> bool:
    p = Path(__file__).resolve().parents[1] / f"data/synthetic_train/{suite}_validated.jsonl"
    return p.exists()


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def render_report(cfg: Config) -> None:
    stages = build_stages(cfg)
    print()
    print("=" * 94)
    print(f" dspy-security-bench — cost estimate (DRY RUN, no LM calls made)")
    print("=" * 94)
    print(f" suites:       {', '.join(cfg.suites)}")
    print(f" attacks:      {', '.join(cfg.attacks)}")
    print(f" optimizers:   {', '.join(cfg.optimizers)}")
    print(f" seeds:        {cfg.seeds}")
    print(f" user × inj:   {cfg.user_tasks_per_suite} × {cfg.injection_tasks_per_suite} per suite")
    print(f" exec model:   {cfg.exec_model}")
    print(f" judge model:  {cfg.judge_model}")
    print(f" reflect lm:   {cfg.reflection_model}")
    print(f" eval runs:    {cfg.n_evals:,}")
    print(f" compile runs: {cfg.n_compiles}")
    print("=" * 94)
    print()
    print(f" {'stage':<68} {'calls':>10} {'cost USD':>10}")
    print(" " + "-" * 92)

    totals_by_stage = {"synthesis": 0.0, "compile": 0.0, "eval": 0.0}
    grand_calls = 0
    grand_cost = 0.0

    for s in stages:
        cost = _stage_cost_usd(s, cfg)
        grand_cost += cost
        grand_calls += s.calls
        print(f" {s.name[:68]:<68} {s.calls:>10,} {cost:>9.2f}")
        if s.notes:
            print(f"   └─ {s.notes}")
        # roll into category buckets
        if s.name.startswith("synthesis"):
            totals_by_stage["synthesis"] += cost
        elif s.name.startswith("compile"):
            totals_by_stage["compile"] += cost
        elif s.name.startswith("evaluation"):
            totals_by_stage["eval"] += cost

    print(" " + "-" * 92)
    print(f" {'TOTAL':<68} {grand_calls:>10,} {grand_cost:>9.2f}")
    print()
    print(" by stage:")
    for stage, cost in totals_by_stage.items():
        pct = (cost / grand_cost * 100) if grand_cost else 0
        print(f"   {stage:<12} ${cost:7.2f}  ({pct:5.1f}%)")
    print()

    # Warnings
    warnings = []
    if grand_cost > 500:
        warnings.append(f"projected cost ${grand_cost:.2f} exceeds $500 — confirm scope before running")
    if cfg.exec_model.startswith("openai/") and cfg.n_evals * 10 > 9_000:
        warnings.append(
            "expected execution-LM calls likely exceed OpenAI Tier 1 daily quota "
            "(10,000 RPD). Confirm Tier 2 or shard the run across days."
        )
    if cfg.n_evals == 0 and not cfg.skip_eval:
        warnings.append("eval matrix is empty — check user_tasks_per_suite / injection_tasks_per_suite > 0")
    if warnings:
        print(" WARNINGS:")
        for w in warnings:
            print(f"   ! {w}")
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> Config:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--preset", choices=list(PRESETS), default="phase2",
                   help="named config (default: phase2). Pass other flags to override.")
    p.add_argument("--suites", nargs="+", help="override suite list")
    p.add_argument("--attacks", nargs="+", help="override attack list")
    p.add_argument("--optimizers", nargs="+", help="override optimizer list")
    p.add_argument("--user-tasks", type=int, dest="user_tasks_per_suite",
                   help="user tasks per (suite × seed × optimizer × attack) cell")
    p.add_argument("--injection-tasks", type=int, dest="injection_tasks_per_suite",
                   help="injection tasks per cell")
    p.add_argument("--seeds", type=int, help="number of optimizer seeds")
    p.add_argument("--synthesis-tasks", type=int, dest="synthesis_tasks_per_suite",
                   help="synthetic tasks generated per new suite (0 if reusing)")
    p.add_argument("--exec-model", help="execution LM (default from preset)")
    p.add_argument("--judge-model", help="LLM-as-judge model")
    p.add_argument("--reflect-model", dest="reflection_model", help="GEPA reflection LM")
    p.add_argument("--skip-synthesis", action="store_true")
    p.add_argument("--skip-compile", action="store_true")
    p.add_argument("--skip-eval", action="store_true")
    p.add_argument("--json", dest="emit_json", action="store_true",
                   help="emit machine-readable JSON instead of the text report")
    args = p.parse_args()

    base = dict(PRESETS[args.preset])
    for k in ("suites", "attacks", "optimizers", "user_tasks_per_suite",
              "injection_tasks_per_suite", "seeds", "synthesis_tasks_per_suite",
              "exec_model", "judge_model", "reflection_model"):
        v = getattr(args, k, None)
        if v is not None:
            base[k] = v
    base["skip_synthesis"] = args.skip_synthesis
    base["skip_compile"] = args.skip_compile
    base["skip_eval"] = args.skip_eval
    return Config(**base), args.emit_json


def main():
    cfg, emit_json = parse_args()
    if emit_json:
        stages = build_stages(cfg)
        payload = {
            "config": {k: v for k, v in cfg.__dict__.items() if k != "stages"},
            "n_evals": cfg.n_evals,
            "n_compiles": cfg.n_compiles,
            "stages": [
                {"name": s.name, "calls": s.calls, "cost_usd": _stage_cost_usd(s, cfg),
                 "model_resolved": _resolve_model(s.model, cfg)}
                for s in stages
            ],
            "total_cost_usd": sum(_stage_cost_usd(s, cfg) for s in stages),
            "total_calls": sum(s.calls for s in stages),
        }
        json.dump(payload, sys.stdout, indent=2)
        print()
    else:
        render_report(cfg)


if __name__ == "__main__":
    main()
