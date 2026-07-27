"""Scaffold-generality check: re-measure robustness with DSPy removed.

Every leaderboard row is produced with `dspy.ReActV2`. The obvious objection is
that the ranking might be an artifact of that one agent implementation — its
prompt format, its reasoning loop, its parser — rather than a property of the
model. This re-runs the same models, the same frozen task subset, the same
attacks and the same decoding settings through a plain native function-calling
agent that does not involve DSPy at all
(`dspy_security_bench.agents.litellm_fc.LiteLLMFunctionCallingAgent`).

If the buckets and the ordering survive the swap, the finding is a property of
the models rather than of the harness.

    uv run python scripts/run_scaffold_check.py --model openrouter/<id>

Writes leaderboard/scaffold_fc/<slug>.json.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import logging
from datetime import date
from pathlib import Path

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("scaffold")

REPO_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = REPO_ROOT / "leaderboard/protocol.yaml"
OUT_DIR = REPO_ROOT / "leaderboard/scaffold_fc"

_spec = importlib.util.spec_from_file_location("rl", Path(__file__).with_name("run_leaderboard.py"))
_rl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rl)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    args = ap.parse_args()

    proto = yaml.safe_load(PROTOCOL_PATH.read_text())
    frozen = proto["frozen"]
    dur = proto["durability"]
    k = dur["repeats_k"]
    suites = frozen["suites"]
    subset = frozen.get("user_task_subset", {})
    head = frozen["headline_attack"]
    entry = _rl._registry_entry(args.model)

    from dspy_security_bench.agents.litellm_fc import LiteLLMFunctionCallingAgent
    from dspy_security_bench.runner import evaluate_agents

    per_suite: dict = {}
    for suite in suites:
        per_suite[suite] = {}
        user_ids = subset.get(suite)
        repeat_cells = []
        for rep in range(k):
            log.info("scaffold=fc suite=%s attack=%s repeat=%d/%d", suite, head, rep + 1, k)
            # A fresh agent per repeat, matching the protocol's decoding settings
            # exactly so the only difference from the board is the scaffold.
            agent = LiteLLMFunctionCallingAgent(
                model=args.model,
                max_iters=frozen["scaffold"]["max_iters"],
                temperature=frozen["decoding"]["temperature"],
                max_tokens=frozen["decoding"]["exec_max_tokens"],
                num_retries=12,
                name="litellm_fc",
            )
            df = evaluate_agents(
                {"litellm_fc": agent},
                suite_name=suite,
                attacks=[head],
                user_task_ids=user_ids,
                injection_task_ids=None,
                defenses=["none"],
                force_rerun=True,
            )
            sub = df[df["attack"] == head]
            repeat_cells.append({
                "security": [int(v) for v in sub["security"].tolist()],
                "utility": [int(v) for v in sub["utility"].tolist()],
            })

        sec_pairs = _rl._collapse_repeats(repeat_cells, "security")
        util_pairs = _rl._collapse_repeats(repeat_cells, "utility")
        lo, hi = _rl._bootstrap_ci(sec_pairs)
        per_suite[suite][head] = {
            "R_mean": round(sum(sec_pairs) / len(sec_pairs), 4) if sec_pairs else 0.0,
            "R_ci_low": round(lo, 4),
            "R_ci_high": round(hi, 4),
            "n_pairs": sum(len(c["security"]) for c in repeat_cells),
            "n_pairs_unique": len(sec_pairs),
            "per_repeat_R": [round(sum(c["security"]) / len(c["security"]), 4)
                             if c["security"] else 0.0 for c in repeat_cells],
            "U_mean": round(sum(util_pairs) / len(util_pairs), 4) if util_pairs else 0.0,
        }

    sc = _rl.score_row(per_suite, head, suites, proto["buckets"], dur, k)
    row = {
        "model_id": entry["model_id"],
        "family": entry["family"],
        "display_name": entry["display_name"],
        "scaffold": "litellm_function_calling",
        "protocol_version": proto["protocol_version"],
        "config_hash": _rl._config_hash(frozen),
        "per_suite": per_suite,
        "combined_R": sc["combined_R"],
        "combined_ci_low": sc["combined_ci_low"],
        "combined_ci_high": sc["combined_ci_high"],
        "bucket": sc["bucket"],
        "status": "confirmed" if sc["confirmed"] else "provisional",
        "ci_basis": "cluster",
        "repeats_k": k,
        "run_dates": [date.today().isoformat()],
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{_rl._slug(entry['model_id'])}.json"
    out.write_text(json.dumps(row, indent=2))
    log.info("wrote %s  R=%.3f bucket=%s", out, sc["combined_R"], sc["bucket"])


if __name__ == "__main__":
    main()
