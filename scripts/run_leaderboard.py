"""Frozen runner for the Model Injection-Robustness Leaderboard.

Measures one model's base (unoptimized, undefended) prompt-injection robustness
under the exact settings frozen in `leaderboard/protocol.yaml`, with k repeats,
a bootstrap CI, and the confirm/provisional stability gate. Writes one result
JSON to `leaderboard/results/<slug>.json`, which `generate_leaderboard.py`
renders into `LEADERBOARD.md`.

This is the ONLY sanctioned way to produce a leaderboard row. It deliberately
hard-codes nothing about the protocol: everything comes from protocol.yaml, so
the board stays internally consistent and a protocol change is a single edit.

Runs are checkpointed. Each (suite, attack, repeat) cell is written to
`leaderboard/.checkpoints/<slug>.json` the moment it finishes, so a crash, a
provider rate-limit abort, or a killed shell resumes from the last completed
cell instead of re-measuring everything. A checkpoint is only reused when the
protocol hash, repeat count, and attack set all match; otherwise it is
discarded rather than mixing incomparable measurements. It is deleted once the
final result JSON is written. Use `--no-resume` to force a clean re-measure.

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
# Partial per-cell results, so an interrupted run resumes instead of restarting.
# Not committed: these are scratch state, superseded by the final result JSON.
CHECKPOINT_DIR = REPO_ROOT / "leaderboard/.checkpoints"


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

    The public claim is the BUCKET, so a row is CONFIRMED iff the combined-R 95%
    CI lies entirely inside one bucket AND the bucket is identical across all k
    repeats — i.e. exactly when the bucket cannot flip. Otherwise PROVISIONAL.

    * combined_R is the coverage-weighted mean over suites.
    * The combined-R CI is obtained by propagating each suite's pooled bootstrap
      CI (SE_s ~= half-width / 1.96) through the weighted mean:
      Var = sum_s (w_s * SE_s)^2. This is honest about cross-suite weighting
      without conflating genuine workspace-vs-banking differences with noise.
    * bucket-stability is judged on the COMBINED per-repeat R, so a model isn't
      called unstable just because two suites sit in different buckets while each
      is itself steady.
    """
    num = sum(per_suite[s][head]["R_mean"] * per_suite[s][head]["n_pairs"] for s in suites)
    den = sum(per_suite[s][head]["n_pairs"] for s in suites) or 1
    combined_r = num / den
    combined_bucket = _bucket(combined_r, buckets)

    var = 0.0
    for s in suites:
        w = per_suite[s][head]["n_pairs"] / den
        se_s = (per_suite[s][head]["R_ci_high"] - per_suite[s][head]["R_ci_low"]) / (2 * 1.96)
        var += (w * se_s) ** 2
    se = var ** 0.5
    ci_low = max(0.0, combined_r - 1.96 * se)
    ci_high = min(1.0, combined_r + 1.96 * se)
    ci_halfwidth = (ci_high - ci_low) / 2

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

    ci_within_bucket = _bucket(ci_low, buckets) == _bucket(ci_high, buckets) == combined_bucket
    confirmed = (ci_within_bucket if dur.get("confirm_ci_within_bucket", True) else True) and (
        bucket_stable if dur["confirm_bucket_stable"] else True
    )
    return {
        "combined_R": round(combined_r, 4),
        "bucket": combined_bucket,
        "combined_ci_low": round(ci_low, 4),
        "combined_ci_high": round(ci_high, 4),
        "ci_halfwidth": round(ci_halfwidth, 4),
        "bucket_stable": bucket_stable,
        "ci_within_bucket": ci_within_bucket,
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


def _ckpt_path(model_id: str) -> Path:
    return CHECKPOINT_DIR / f"{_slug(model_id)}.json"


def _load_checkpoint(model_id: str, cfg_hash: str, k: int, attacks: list) -> dict:
    """Return completed cells for this model, or {} if there is no usable one.

    A checkpoint is only reused when it was produced by the *same* protocol
    (config hash), repeat count, and attack set. Anything else is discarded
    rather than silently mixing incomparable measurements into one row.
    """
    p = _ckpt_path(model_id)
    if not p.exists():
        return {}
    try:
        ck = json.loads(p.read_text())
    except Exception:
        log.warning("checkpoint unreadable, starting fresh")
        return {}
    if (ck.get("config_hash") != cfg_hash or ck.get("repeats_k") != k
            or ck.get("attacks") != list(attacks)):
        log.warning("checkpoint is from a different protocol/config — discarding it")
        return {}
    cells = ck.get("cells", {})
    if cells:
        log.info("resuming from checkpoint: %d/%d cells already done",
                 len(cells), len(attacks) * k * len(ck.get("suites", [])) or len(cells))
    return cells


def _save_checkpoint(model_id: str, cfg_hash: str, k: int, attacks: list,
                     suites: list, cells: dict) -> None:
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "model_id": model_id,
        "config_hash": cfg_hash,
        "repeats_k": k,
        "attacks": list(attacks),
        "suites": list(suites),
        "cells": cells,
    }
    # Write-then-rename so a crash mid-write cannot corrupt the checkpoint.
    tmp = _ckpt_path(model_id).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload))
    tmp.replace(_ckpt_path(model_id))


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
    ap.add_argument("--no-resume", action="store_true",
                    help="ignore any checkpoint and re-measure every cell from scratch")
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
    # Frozen subset: the pinned user-task list per suite, all injection tasks
    # (inj_ids=None lets the harness use every injection task). Smoke uses a tiny
    # slice. The subset is per-suite, resolved inside the loop below.
    subset = frozen.get("user_task_subset", {})

    log.info("model=%s protocol=%s cfg_hash=%s", args.model,
             proto["protocol_version"], cfg_hash)
    log.info("suites=%s attacks=%s k=%d max_iters=%d coverage=%s",
             suites, attacks, k, max_iters,
             "smoke-2x1" if args.smoke else f"subset({frozen.get('task_coverage')})")
    if args.plan:
        log.info("plan only — no LM calls made. Exiting.")
        return

    if entry.get("provider_env") and not os.environ.get(entry["provider_env"]):
        log.warning("env var %s is not set; the run will fail if the provider "
                    "needs it", entry["provider_env"])

    import dspy

    from dspy_security_bench.optimizers import _make_agent_factory

    lm_kwargs = {}
    if args.model.startswith("openrouter/"):
        # OpenRouter multiplexes each model across several upstream providers and
        # will silently fall back to one that can't serve tool-calling/structured
        # output, which crashes the ReAct scaffold. Novita in particular accepts
        # the request but then rejects it ("does not support endpoint:
        # completions"), so it is excluded outright; require_parameters keeps
        # routing to providers that support the request's parameters. This is a
        # routing/resilience setting; it does not change what is measured.
        lm_kwargs["extra_body"] = {
            "provider": {"require_parameters": True, "ignore": ["Novita"]}
        }

    exec_lm = dspy.LM(
        args.model,
        temperature=frozen["decoding"]["temperature"],
        max_tokens=frozen["decoding"]["exec_max_tokens"],
        # High retry count (exponential backoff) so a provider's per-second/minute
        # rate window is ridden out rather than crashing the run. This is a
        # resilience knob only; it does not affect what is measured.
        num_retries=12,
        **lm_kwargs,
    )
    dspy.configure(lm=exec_lm)
    factory_fn = _make_agent_factory(None, base_signature=frozen["scaffold"]["base_signature"])

    # Completed (suite|attack|repeat) cells from a previous interrupted run.
    cells: dict = {} if args.no_resume else _load_checkpoint(args.model, cfg_hash, k, attacks)

    # per_suite[suite][attack] = {R_mean, R_ci_low, R_ci_high, n_pairs, per_repeat_R}
    per_suite: dict = {}
    run_dates = [date.today().isoformat()]  # one run session; k repeats within it
    for suite in suites:
        per_suite[suite] = {}
        # Frozen subset user tasks for this suite; smoke uses a tiny 2-task slice.
        user_ids = ["user_task_0", "user_task_1"] if args.smoke else subset.get(suite)
        inj_ids = ["injection_task_0"] if args.smoke else None  # None => all injections
        for attack in attacks:
            repeat_pairs: list[list[int]] = []
            for rep in range(k):
                cell_key = f"{suite}|{attack}|{rep}"
                cached = cells.get(cell_key)
                if cached is not None:
                    log.info("skip suite=%s attack=%s repeat=%d/%d (checkpointed, %d pairs)",
                             suite, attack, rep + 1, k, len(cached))
                    repeat_pairs.append(list(cached))
                    continue
                log.info("run suite=%s attack=%s repeat=%d/%d (users=%s)", suite, attack,
                         rep + 1, k, "subset-2" if args.smoke else f"{len(user_ids or [])}")
                vals = _run_one_cell(factory_fn, suite, attack, max_iters, user_ids, inj_ids)
                repeat_pairs.append(vals)
                # Persist immediately: this cell cost real tokens and minutes, and
                # must survive a crash, a rate-limit abort, or a session teardown.
                cells[cell_key] = vals
                _save_checkpoint(args.model, cfg_hash, k, attacks, suites, cells)
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
        "combined_ci_low": sc["combined_ci_low"],
        "combined_ci_high": sc["combined_ci_high"],
        "bucket": combined_bucket,
        "status": status,
        "repeats_k": k,
        "greedy_honored": "unknown",  # provider-dependent; refined post-run if known
        "run_dates": run_dates,
        "ci_halfwidth": round(ci_halfwidth, 4),
        "ci_within_bucket": sc["ci_within_bucket"],
        "bucket_stable": bucket_stable,
        "combined_per_repeat_R": sc["combined_per_repeat_R"],
        "smoke": bool(args.smoke),
        "trace_refs": {"config_hash": cfg_hash},
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    suffix = "_smoke" if args.smoke else ""
    out = RESULTS_DIR / f"{_slug(entry['model_id'])}{suffix}.json"
    out.write_text(json.dumps(row, indent=2))
    # The row is now the durable artifact; the checkpoint has served its purpose.
    _ckpt_path(args.model).unlink(missing_ok=True)
    log.info("wrote %s", out)
    log.info("combined_R=%.3f bucket=%s status=%s ci_halfwidth=%.3f",
             combined_r, combined_bucket, status, ci_halfwidth)


if __name__ == "__main__":
    main()
