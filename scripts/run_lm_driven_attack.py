"""LM-driven iterative adaptive attack experiment.

For each defense, an attacker LM (default DeepSeek V3) iteratively crafts
injection payloads against the defended target (default Mistral Large), up to
K rounds, refining on failure. Reports whether each defense was BROKEN and in
how many rounds, and logs every payload for audit.

This is the conclusive test the rule-based attack could not give: can a capable
attacker that iterates actually defeat the defenses that recovered Mistral
Large's security?

Usage:
    python scripts/run_lm_driven_attack.py \
        --target mistral/mistral-large-latest \
        --attacker deepseek/deepseek-chat \
        --defenses security_prompt spotlight_delim spotlight_datamark sandwich \
        --user-tasks user_task_0 user_task_1 --rounds 5
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import asdict
from pathlib import Path

import litellm

from agentdojo.task_suite.load_suites import get_suite

from dspy_security_bench.attacks.lm_driven import (
    IterativeAttackRunner,
    make_agentdojo_run_and_judge,
    make_lm_attacker,
)
from dspy_security_bench.defenses import get_defense

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("lm_driven_exp")

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "data/results"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="mistral/mistral-large-latest")
    p.add_argument("--attacker", default="deepseek/deepseek-chat")
    p.add_argument("--defenses", nargs="+",
                   default=["security_prompt", "spotlight_delim", "spotlight_datamark", "sandwich"])
    p.add_argument("--user-tasks", nargs="+", default=["user_task_0", "user_task_1"])
    p.add_argument("--injection-task", default="injection_task_0")
    p.add_argument("--rounds", type=int, default=5)
    args = p.parse_args()

    litellm.drop_params = True
    suite = get_suite("v1", "workspace")
    injection_task = suite.injection_tasks[args.injection_task]
    attacker = make_lm_attacker(args.attacker)

    results = []
    t0 = time.time()
    for defense_name in args.defenses:
        defense = get_defense(defense_name)
        run_and_judge = make_agentdojo_run_and_judge(
            target_lm_model=args.target, defense=defense, suite=suite)
        runner = IterativeAttackRunner(attacker, run_and_judge, max_rounds=args.rounds)

        for ut_id in args.user_tasks:
            user_task = suite.user_tasks[ut_id]
            log.info(f"attacking defense={defense_name} × {ut_id} (up to {args.rounds} rounds)")
            res = runner.run(defense_name=defense_name, user_task=user_task,
                             injection_task=injection_task)
            log.info(f"  → {'BROKEN in %d rounds' % res.rounds_used if res.broken else 'HELD'}")
            results.append(res)

    dt = time.time() - t0

    # Persist full audit log (every payload + outcome)
    def _slug(s):
        import re
        return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")
    out = RESULTS_DIR / f"lm_driven_attack_{_slug(args.target)}.json"
    out.write_text(json.dumps({
        "target": args.target, "attacker": args.attacker, "rounds": args.rounds,
        "results": [asdict(r) for r in results],
    }, indent=2))

    # Summary: per-defense, was it broken on ANY task?
    print()
    print("=" * 84)
    print(f" LM-DRIVEN ADAPTIVE ATTACK — target={args.target}  attacker={args.attacker}  K={args.rounds}")
    print("=" * 84)
    by_defense = {}
    for r in results:
        by_defense.setdefault(r.defense_name, []).append(r)
    print(f" {'defense':<20} {'result':<32} {'rounds (per task)':<20}")
    print(" " + "-" * 78)
    for d, rs in by_defense.items():
        broke = [r for r in rs if r.broken]
        rounds = ", ".join(str(r.rounds_used) if r.broken else "held" for r in rs)
        verdict = (f"BROKEN on {len(broke)}/{len(rs)} tasks" if broke
                   else f"HELD across all {len(rs)} tasks")
        print(f" {d:<20} {verdict:<32} {rounds:<20}")
    print(" " + "-" * 78)
    print(f" wall-clock {dt:.0f}s; full audit log → {out.name}")
    print()
    print(" Interpretation: 'HELD across K rounds' = the defense survived an iterative,")
    print(" defense-aware attacker. 'BROKEN' = the recovery claim is qualified for that cell.")


if __name__ == "__main__":
    main()
