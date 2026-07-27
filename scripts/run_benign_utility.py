"""Measure each model's benign task competence — the capability axis.

The leaderboard answers "does the injection fail?". On its own that is not
interpretable: a model that cannot do anything scores a perfect security rate.
This script measures the other axis on the *same* tasks, the *same* scaffold and
the *same* frozen subset, with no injections present at all:

    U_benign = fraction of user tasks the agent completes correctly, unattacked.

Having both lets the paper make the central claim quantitatively rather than by
eyeball: if robustness were merely a by-product of capability, R and U_benign
would be strongly correlated. Measuring capability in-house on identical tasks
also avoids leaning on external leaderboard scores, which are a moving target and
are not measured under this scaffold.

    uv run python scripts/run_benign_utility.py --model openrouter/<id>

Writes leaderboard/benign/<slug>.json.
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
log = logging.getLogger("benign")

REPO_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = REPO_ROOT / "leaderboard/protocol.yaml"
OUT_DIR = REPO_ROOT / "leaderboard/benign"

# Reuse the leaderboard runner's helpers so slugs, CIs and registry lookups are
# identical to the security-side numbers they will be compared against.
_spec = importlib.util.spec_from_file_location("rl", Path(__file__).with_name("run_leaderboard.py"))
_rl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rl)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    args = ap.parse_args()

    proto = yaml.safe_load(PROTOCOL_PATH.read_text())
    frozen = proto["frozen"]
    k = proto["durability"]["repeats_k"]
    suites = frozen["suites"]
    subset = frozen.get("user_task_subset", {})
    max_iters = frozen["scaffold"]["max_iters"]
    entry = _rl._registry_entry(args.model)

    import dspy
    from agentdojo.benchmark import benchmark_suite_without_injections
    from agentdojo.task_suite.load_suites import get_suite

    from dspy_security_bench.optimizers import _make_agent_factory
    from dspy_security_bench.runner import _build_pipeline

    lm_kwargs = {}
    if args.model.startswith("openrouter/"):
        provider_cfg: dict = {"ignore": ["Novita"]}
        if entry.get("routing") != "relaxed":
            provider_cfg["require_parameters"] = True
        lm_kwargs["extra_body"] = {"provider": provider_cfg}

    dspy.configure(lm=dspy.LM(
        args.model,
        temperature=frozen["decoding"]["temperature"],
        max_tokens=frozen["decoding"]["exec_max_tokens"],
        num_retries=12,
        **lm_kwargs,
    ))
    factory = _make_agent_factory(None, base_signature=frozen["scaffold"]["base_signature"])

    per_suite: dict = {}
    for suite_name in suites:
        suite = get_suite(frozen["agentdojo_benchmark_version"], suite_name)
        user_tasks = subset.get(suite_name)
        repeats: list[list[int]] = []
        for rep in range(k):
            log.info("benign suite=%s repeat=%d/%d (%d user tasks)",
                     suite_name, rep + 1, k, len(user_tasks or []))
            pipeline = _build_pipeline(
                factory, "gpt-4o-mini-2024-07-18", max_iters, None, defense=None
            )
            res = benchmark_suite_without_injections(
                agent_pipeline=pipeline,
                suite=suite,
                logdir=None,
                force_rerun=True,
                user_tasks=list(user_tasks) if user_tasks else None,
                benchmark_version=frozen["agentdojo_benchmark_version"],
            )
            utility = res.get("utility_results", {}) if isinstance(res, dict) else res.utility_results
            repeats.append([int(bool(v)) for v in utility.values()])

        pooled = [v for r in repeats for v in r]
        u = sum(pooled) / len(pooled) if pooled else 0.0
        lo, hi = _rl._bootstrap_ci(pooled)
        per_suite[suite_name] = {
            "U_benign": round(u, 4),
            "U_ci_low": round(lo, 4),
            "U_ci_high": round(hi, 4),
            "n_tasks": len(pooled),
            "per_repeat_U": [round(sum(r) / len(r), 4) if r else 0.0 for r in repeats],
        }

    den = sum(per_suite[s]["n_tasks"] for s in suites) or 1
    combined = sum(per_suite[s]["U_benign"] * per_suite[s]["n_tasks"] for s in suites) / den

    row = {
        "model_id": entry["model_id"],
        "family": entry["family"],
        "display_name": entry["display_name"],
        "protocol_version": proto["protocol_version"],
        "config_hash": _rl._config_hash(frozen),
        "combined_U_benign": round(combined, 4),
        "per_suite": per_suite,
        "repeats_k": k,
        "run_dates": [date.today().isoformat()],
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{_rl._slug(entry['model_id'])}.json"
    out.write_text(json.dumps(row, indent=2))
    log.info("wrote %s  U_benign=%.3f", out, combined)


if __name__ == "__main__":
    main()
