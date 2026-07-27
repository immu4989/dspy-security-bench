"""Re-derive the confirm/provisional verdict for existing leaderboard results.

The per-suite statistics in each result JSON (R_mean, per-suite CIs, per_repeat_R,
n_pairs) are the ground truth and are never changed here. Only the *derived*
fields — combined_R, bucket, ci_halfwidth, bucket_stable, status — are recomputed,
using the exact same `score_row` the runner uses. Run this after a scoring-logic
fix so already-measured rows pick it up without any re-run.

    uv run python scripts/rescore_leaderboard.py           # rewrite in place
    uv run python scripts/rescore_leaderboard.py --dry-run # show changes only
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "leaderboard/results"
PROTOCOL_PATH = REPO_ROOT / "leaderboard/protocol.yaml"

# Import score_row from the runner so the two can never diverge.
_spec = importlib.util.spec_from_file_location("run_leaderboard", Path(__file__).with_name("run_leaderboard.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
score_row = _mod.score_row
_bootstrap_ci = _mod._bootstrap_ci


def _fix_repeat_inflated_ci(row: dict, k: int) -> None:
    """Recompute per-suite CIs that were bootstrapped over pooled repeats.

    Rows produced before the cluster-bootstrap fix resampled k*n observations as
    if they were independent, when the independent unit is the task pair. That
    understates every interval by roughly sqrt(k) and made the confirm gate far
    too permissive (it wrongly confirmed 5 of 14 rows).

    The raw per-pair values are not retained in the result JSON, so the pair-level
    vector is reconstructed from the cell mean over n_pairs/k unique pairs. This
    is exact whenever the k repeats were identical, which held for 54 of 56
    measured cells. Where repeats differed, the true per-pair values include
    fractions (e.g. 2/3), which have strictly lower variance than the 0/1 vector
    reconstructed here — so the recomputed interval is conservative, never
    optimistic. Rows already carrying `ci_basis == "cluster"` are left alone.
    """
    if row.get("ci_basis") == "cluster":
        return
    for suite, attacks in row.get("per_suite", {}).items():  # noqa: B007 - suite unused
        for cell in attacks.values():
            n_unique = max(1, cell["n_pairs"] // k)
            for mean_key, lo_key, hi_key in (("R_mean", "R_ci_low", "R_ci_high"),
                                             ("U_mean", "U_ci_low", "U_ci_high")):
                if mean_key not in cell:
                    continue
                ones = round(cell[mean_key] * n_unique)
                vec = [1.0] * ones + [0.0] * (n_unique - ones)
                lo, hi = _bootstrap_ci(vec)
                cell[lo_key], cell[hi_key] = round(lo, 4), round(hi, 4)
            cell["n_pairs_unique"] = n_unique
    row["ci_basis"] = "cluster"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    proto = yaml.safe_load(PROTOCOL_PATH.read_text())
    frozen = proto["frozen"]
    head = frozen["headline_attack"]
    suites = frozen["suites"]

    for f in sorted(RESULTS_DIR.glob("*.json")):
        row = json.loads(f.read_text())
        k = row.get("repeats_k", proto["durability"]["repeats_k"])
        # Only score over suites actually present (a partial row is left as-is).
        present = [s for s in suites if s in row.get("per_suite", {}) and head in row["per_suite"][s]]
        if not present:
            continue
        _fix_repeat_inflated_ci(row, k)
        sc = score_row(row["per_suite"], head, present, proto["buckets"], proto["durability"], k)
        new_status = "confirmed" if (sc["confirmed"] and not row.get("smoke")) else "provisional"
        old = (row.get("status"), row.get("ci_halfwidth"), row.get("bucket"))
        new = (new_status, sc["ci_halfwidth"], sc["bucket"])
        if old != new:
            print(f"{f.name}: {old} -> {new}")
        if not args.dry_run:
            row.update({
                "combined_R": sc["combined_R"],
                "combined_ci_low": sc["combined_ci_low"],
                "combined_ci_high": sc["combined_ci_high"],
                "bucket": sc["bucket"],
                "ci_halfwidth": sc["ci_halfwidth"],
                "ci_within_bucket": sc["ci_within_bucket"],
                "bucket_stable": sc["bucket_stable"],
                "combined_per_repeat_R": sc["combined_per_repeat_R"],
                "status": new_status,
            })
            f.write_text(json.dumps(row, indent=2))

    if args.dry_run:
        print("(dry run — no files written)")


if __name__ == "__main__":
    main()
