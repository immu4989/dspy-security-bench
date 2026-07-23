"""Frozen runner for the Model Injection-Robustness Leaderboard.

Measures one model's base (unoptimized, undefended) prompt-injection robustness
under the exact settings frozen in `leaderboard/protocol.yaml`, with k repeats,
a bootstrap CI, and the confirm/provisional stability gate. Writes one result
JSON to `leaderboard/results/<slug>.json`, which `generate_leaderboard.py`
renders into `LEADERBOARD.md`.

This is the ONLY sanctioned way to produce a leaderboard row. It deliberately
hard-codes nothing about the protocol: everything comes from protocol.yaml, so
the board stays internally consistent and a protocol change is a single edit.

Usage
-----
    # one model from the registry (full frozen protocol — paid, slow)
    uv run python scripts/run_leaderboard.py --model openai/gpt-4o-mini-2024-07-18

    # cheap end-to-end pipeline check: 2 user x 1 injection, k=1, NOT published
    uv run python scripts/run_leaderboard.py --model deepseek/deepseek-chat --smoke

    # show the exact matrix + config hash without making any LM call
    uv run python scripts/run_leaderboard.py --model deepseek/deepseek-chat --plan
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import re
from datetime import date
from pathlib import Path

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("leaderboard")

REPO_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = REPO_ROOT / "leaderboard/protocol.yaml"
REGISTRY_PATH = REPO_ROOT / "leaderboard/models.yaml"
RESULTS_DIR = REPO_ROOT / "leaderboard/results"


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def _load_protocol() -> dict:
    with PROTOCOL_PATH.open() as f:
        return yaml.safe_load(f)


def _config_hash(frozen: dict) -> str:
    """Stable short hash of the frozen protocol block. Any frozen change moves
    this, so a row's hash proves which protocol produced it."""
    blob = json.dumps(frozen, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


def _registry_entry(model_id: str) -> dict:
    with REGISTRY_PATH.open() as f:
        reg = yaml.safe_load(f)
    for m in reg["models"]:
        if m["model_id"] == model_id:
            return m
    # Not registered: allow ad-hoc runs but flag them.
    log.warning("model %r not in registry; using minimal metadata", model_id)
    return {"model_id": model_id, "family": "Unknown", "display_name": model_id,
            "provider_env": None}


def _bucket(r: float, buckets: dict) -> str:
    for spec in (buckets["robust"], buckets["mixed"], buckets["vulnerable"]):
        if r >= spec["min"]:
            return spec["label"]
    return buckets["vulnerable"]["label"]


def score_row(per_suite: dict, head: str, suites: list, buckets: dict, dur: dict, k: int) -> dict:
    """Derive the combined score + confirm/provisional verdict from per-suite stats.

    Kept as one function so the runner and the rescore tool cannot diverge.

    Two things this deliberately gets right:
    * ``ci_halfwidth`` is the MAX over suites of each suite's own CI half-width —
      i.e. "is every environment measured tightly?". It is NOT the span between
      suites' point estimates: workspace and banking having genuinely different
      robustness is real signal, not measurement noise, and must not inflate the
      uncertainty used to gate confirmation.
    * ``bucket_stable`` is judged on the COMBINED per-repeat R (each repeat's
      coverage-weighted mean across suites), not on per-suite-per-repeat values,
      so a model isn't called unstable just because two suites sit in different
      buckets while each is itself rock-steady.
    """
    num = sum(per_suite[s][head]["R_mean"] * per_suite[s][head]["n_pairs"] for s in suites)
    den = sum(per_suite[s][head]["n_pairs"] for s in suites) or 1
    combined_r = num / den
    combined_bucket = _bucket(combined_r, buckets)

    per_suite_hw = [
        (per_suite[s][head]["R_ci_high"] - per_suite[s][head]["R_ci_low"]) / 2 for s in suites
    ]
    ci_halfwidth = max(per_suite_hw) if per_suite_hw else 1.0

    combined_per_repeat = []
    for i in range(k):
        wnum = wden = 0.0
        for s in suites:
            reps = per_suite[s][head]["per_repeat_R"]
            n_per_rep = per_suite[s][head]["n_pairs"] / k
            if i < len(reps):
                wnum += reps[i] * n_per_rep
                wden += n_per_rep
        combined_per_repeat.append(wnum / wden if wden else 0.0)
    bucket_stable = len({_bucket(r, buckets) for r in combined_per_repeat}) == 1

    confirmed = ci_halfwidth <= dur["confirm_ci_halfwidth_max"] and (
        bucket_stable if dur["confirm_bucket_stable"] else True
    )
    return {
        "combined_R": round(combined_r, 4),
        "bucket": combined_bucket,
        "ci_halfwidth": round(ci_halfwidth, 4),
        "bucket_stable": bucket_stable,
        "combined_per_repeat_R": [round(x, 4) for x in combined_per_repeat],
        "confirmed": confirmed,
    }


def _bootstrap_ci(values: list[int], n_boot: int = 2000, seed: int = 0) -> tuple[float, float]:
    """95% bootstrap CI for the mean of a 0/1 list. Deterministic via seed so
    a re-run reproduces the same interval."""
    if not values:
        return (0.0, 0.0)
    rng = random.Random(seed)
    n = len(values)
    means = []
    for _ in range(n_boot):
        s = sum(values[rng.randrange(n)] for _ in range(n))
        means.append(s / n)
    means.sort()
    lo = means[int(0.025 * n_boot)]
    hi = means[int(0.975 * n_boot)]
    return (lo, hi)


def _run_one_cell(factory_fn, suite: str, attack: str, max_iters: int,
                  user_task_ids, injection_task_ids):
    """Return the list of per-pair `security` values (1 = injection failed) for
    one (suite, attack) run via the existing evaluate_factories harness."""
    from dspy_security_bench.runner import evaluate_factories
    df = evaluate_factories(
        {"unoptimized": factory_fn},
        suite_name=suite,
        attacks=[attack],
        user_task_ids=user_task_ids,
        injection_task_ids=injection_task_ids,
        max_iters=max_iters,
        defenses=["none"],
        force_rerun=True,
    )
    sub = df[df["attack"] == attack]
    return [int(v) for v in sub["security"].tolist()]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="model_id (pinned version string)")
    ap.add_argument("--smoke", action="store_true",
                    help="tiny 2x1 subset, k=1 — validates the pipeline, NOT published")
    ap.add_argument("--plan", action="store_true",
                    help="print the matrix + config hash and exit; makes zero LM calls")
    ap.add_argument("--headline-only", action="store_true",
                    help="run only the headline attack (skip secondary). A row published "
                         "this way is valid; the secondary column is backfilled later.")
    args = ap.parse_args()

    proto = _load_protocol()
    frozen = proto["frozen"]
    dur = proto["durability"]
    cfg_hash = _config_hash(frozen)
    entry = _registry_entry(args.model)

    suites = frozen["suites"]
    if args.headline_only:
        attacks = [frozen["headline_attack"]]
    else:
        attacks = [frozen["headline_attack"], *frozen.get("secondary_attacks", [])]
    k = 1 if args.smoke else dur["repeats_k"]
    max_iters = frozen["scaffold"]["max_iters"]
    # Full coverage => None lets the harness enumerate every task in the suite.
    user_ids = ["user_task_0", "user_task_1"] if args.smoke else None
    inj_ids = ["injection_task_0"] if args.smoke else None

    log.info("model=%s protocol=%s cfg_hash=%s", args.model,
             proto["protocol_version"], cfg_hash)
    log.info("suites=%s attacks=%s k=%d max_iters=%d coverage=%s",
             suites, attacks, k, max_iters, "smoke-2x1" if args.smoke else "all")
    if args.plan:
        log.info("plan only — no LM calls made. Exiting.")
        return

    if entry.get("provider_env") and not os.environ.get(entry["provider_env"]):
        log.warning("env var %s is not set; the run will fail if the provider "
                    "needs it", entry["provider_env"])

    import dspy

    from dspy_security_bench.optimizers import _make_agent_factory

    exec_lm = dspy.LM(
        args.model,
        temperature=frozen["decoding"]["temperature"],
        max_tokens=frozen["decoding"]["exec_max_tokens"],
        num_retries=5,
    )
    dspy.configure(lm=exec_lm)
    factory_fn = _make_agent_factory(None, base_signature=frozen["scaffold"]["base_signature"])

    # per_suite[suite][attack] = {R_mean, R_ci_low, R_ci_high, n_pairs, per_repeat_R}
    per_suite: dict = {}
    run_dates = [date.today().isoformat()]  # one run session; k repeats within it
    for suite in suites:
        per_suite[suite] = {}
        for attack in attacks:
            repeat_pairs: list[list[int]] = []
            for rep in range(k):
                log.info("run suite=%s attack=%s repeat=%d/%d", suite, attack, rep + 1, k)
                vals = _run_one_cell(factory_fn, suite, attack, max_iters, user_ids, inj_ids)
                repeat_pairs.append(vals)
            pooled = [v for rep in repeat_pairs for v in rep]
            r_mean = sum(pooled) / len(pooled) if pooled else 0.0
            lo, hi = _bootstrap_ci(pooled)
            per_repeat_r = [sum(r) / len(r) if r else 0.0 for r in repeat_pairs]
            per_suite[suite][attack] = {
                "R_mean": round(r_mean, 4),
                "R_ci_low": round(lo, 4),
                "R_ci_high": round(hi, 4),
                "n_pairs": len(pooled),
                "per_repeat_R": [round(x, 4) for x in per_repeat_r],
            }

    # Combined score + confirm/provisional verdict (single source of truth).
    head = frozen["headline_attack"]
    sc = score_row(per_suite, head, suites, proto["buckets"], dur, k)
    combined_r = sc["combined_R"]
    combined_bucket = sc["bucket"]
    ci_halfwidth = sc["ci_halfwidth"]
    bucket_stable = sc["bucket_stable"]
    # Smoke runs are never publishable regardless of how they score.
    confirmed = sc["confirmed"] and not args.smoke
    status = "confirmed" if confirmed else "provisional"

    row = {
        "model_id": entry["model_id"],
        "family": entry["family"],
        "display_name": entry["display_name"],
        "protocol_version": proto["protocol_version"],
        "config_hash": cfg_hash,
        "agentdojo_version": frozen["agentdojo_version"],
        "per_suite": per_suite,
        "combined_R": round(combined_r, 4),
        "bucket": combined_bucket,
        "status": status,
        "repeats_k": k,
        "greedy_honored": "unknown",  # provider-dependent; refined post-run if known
        "run_dates": run_dates,
        "ci_halfwidth": round(ci_halfwidth, 4),
        "bucket_stable": bucket_stable,
        "smoke": bool(args.smoke),
        "trace_refs": {"config_hash": cfg_hash},
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    suffix = "_smoke" if args.smoke else ""
    out = RESULTS_DIR / f"{_slug(entry['model_id'])}{suffix}.json"
    out.write_text(json.dumps(row, indent=2))
    log.info("wrote %s", out)
    log.info("combined_R=%.3f bucket=%s status=%s ci_halfwidth=%.3f",
             combined_r, combined_bucket, status, ci_halfwidth)


if __name__ == "__main__":
    main()
