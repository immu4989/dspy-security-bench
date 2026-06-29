"""Push v0.1 + v0.1.1 benchmark result CSVs to HuggingFace Hub.

Bundles all evaluation outputs from the v0.1 launch and the v0.1.1 seed
sanity check into one HF dataset so the raw numbers are public,
permanent, and citable independent of the benchmark repo.

Files shipped:
  - workspace_v01_results.csv         # original v0.1 (seed=0, 3 optimizers)
  - workspace_v01_summary.csv         # v0.1 (optimizer × attack) summary
  - workspace_v02_phase1_results.csv  # seed=0 with GEPA added
  - workspace_v02_phase1_summary.csv  # seed=0 with GEPA summary
  - workspace_v02_phase1_seed{1,2}_results.csv  # additional seeds
  - workspace_v02_phase1_seeds_all.csv          # combined 3-seed long table
  - workspace_v02_phase1_seeds_summary.csv      # mean ± std per cell

Run AFTER `hf auth login`:
    python scripts/push_v01_results_to_hf.py
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "data/results"
DEFAULT_REPO = "immu4989/dspy-security-bench-v01-results"

FILES = [
    "workspace_v01_results.csv",
    "workspace_v01_summary.csv",
    "workspace_v02_phase1_results.csv",
    "workspace_v02_phase1_summary.csv",
    "workspace_v02_phase1_seed1_results.csv",
    "workspace_v02_phase1_seed2_results.csv",
    "workspace_v02_phase1_seeds_all.csv",
    "workspace_v02_phase1_seeds_summary.csv",
]

DATASET_CARD = """\
---
license: apache-2.0
task_categories:
  - question-answering
language:
  - en
tags:
  - dspy
  - agentdojo
  - prompt-injection
  - security
  - benchmark
  - evaluation-results
size_categories:
  - n<1K
---

# dspy-security-bench: v0.1 + v0.1.1 results

Raw evaluation outputs from
[`dspy-security-bench`](https://github.com/immu4989/dspy-security-bench).
Cite or audit these numbers without needing to clone the repo or re-run
the benchmark.

## What's in here

| File | Contents | Rows |
|------|----------|-----:|
| `workspace_v01_results.csv` | Original v0.1 launch run. Workspace suite, 3 optimizers (unoptimized, BootstrapFewShot, MIPROv2 light), 2 attacks (direct, important_instructions), N=5 user × 1 injection × 1 seed. | 30 |
| `workspace_v01_summary.csv` | v0.1 (optimizer × attack) summary. utility_rate and security_rate. | 6 |
| `workspace_v02_phase1_results.csv` | v0.1.1 phase 1: same scope as v0.1 plus GEPA. seed=0. | 40 |
| `workspace_v02_phase1_summary.csv` | v0.1.1 phase 1 (optimizer × attack) summary. | 8 |
| `workspace_v02_phase1_seed{1,2}_results.csv` | v0.1.1 sanity check: re-evaluations with optimizer seeds 1 and 2. | 40 each |
| `workspace_v02_phase1_seeds_all.csv` | All three seeds concatenated. Long format with `seed` column. | 120 |
| `workspace_v02_phase1_seeds_summary.csv` | Mean ± std per (optimizer × attack) across 3 seeds. THE GATE TABLE. | 8 |

## How to read the gate table

`workspace_v02_phase1_seeds_summary.csv` is the headline artifact from the
v0.1.1 correction. The columns:

| Column | Meaning |
|--------|---------|
| `optimizer` | unoptimized, bootstrap_fewshot, miprov2, gepa |
| `attack` | direct (lighter) or important_instructions (harder) |
| `utility_mean` / `utility_std` | task success rate, mean and stddev across 3 seeds |
| `security_mean` / `security_std` | attack failure rate, mean and stddev across 3 seeds |
| `n_seeds` | number of optimizer seeds aggregated (3 for stochastic, 1 for unoptimized/bootstrap_fewshot since bootstrap is deterministic on a fixed trainset) |
| `n_runs` | total eval runs (n_seeds × user_tasks × injection_tasks) |

## What v0.1 vs v0.1.1 changed

v0.1's single-seed run reported a clean monotonic security ordering:
`BootstrapFewShot > MIPROv2 > GEPA`. v0.1.1's 3-seed sanity check
falsified this. With seeds aggregated, `BootstrapFewShot` is actually the
*lowest* security on `important_instructions` (0.600), and `MIPROv2` and
`GEPA` tie at 0.733. Standard deviations land in 0.4 to 0.5, so the
individual rankings here are noise-dominated at N=5 user tasks.

What does survive across seeds:
- `unoptimized` gets 0% utility on every seed.
- `BootstrapFewShot` Pareto-dominates on `direct` (60% utility, 100% security).
- Every optimizer trends below `unoptimized`'s 80% security baseline on `important_instructions` (within std bars).

## Caveats

- **Underpowered at this scale.** N=5 user tasks × 1 injection × 3 seeds = 15 runs per cell is dominated by variance. Do not use these numbers to make production deployment decisions about specific optimizers. They show methodology, not deployment guidance.
- **Single model.** Execution + judge both used `gpt-4o-mini`. Different model families may show different patterns.
- **One suite.** Workspace only. v0.2 phase 2 extends to banking, travel, slack.
- **Two attacks.** AgentDojo ships 17. v0.2 phase 2 adds `tool_knowledge` and `ignore_previous`.

## Related artifacts

- Benchmark repo: https://github.com/immu4989/dspy-security-bench
- Trainset (HF): https://huggingface.co/datasets/immu4989/dspy-security-bench-trainset-workspace
- v0.1 launch blog: https://imranahamed.substack.com/p/does-dspy-prompt-optimization-weaken
- v0.1.1 release notes: https://github.com/immu4989/dspy-security-bench/releases/tag/v0.1.1
- v0.2 phase 2 plan: https://github.com/immu4989/dspy-security-bench/issues/1

## License

Apache 2.0, matching the benchmark repo.
"""


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", default=DEFAULT_REPO, help=f"HF repo id (default: {DEFAULT_REPO})")
    p.add_argument("--private", action="store_true", help="create as private (default: public)")
    p.add_argument("--dry-run", action="store_true", help="show what would happen without uploading")
    args = p.parse_args()

    try:
        from huggingface_hub import HfApi, create_repo, whoami
    except ImportError:
        sys.exit("huggingface_hub not installed. Run: uv pip install huggingface_hub")

    try:
        user = whoami()
    except Exception as e:
        sys.exit(f"Not authenticated. Run `hf auth login` first. ({type(e).__name__}: {e})")
    print(f"Authenticated as {user.get('name', '?')}")

    paths = []
    for name in FILES:
        p_ = RESULTS_DIR / name
        if not p_.exists():
            sys.exit(f"missing result file: {p_}")
        paths.append(p_)
    print(f"Found {len(paths)} result files in {RESULTS_DIR}/")

    if args.dry_run:
        print(f"DRY RUN — would push to {'private' if args.private else 'public'} repo {args.repo}")
        for p_ in paths:
            print(f"  - {p_.name} ({p_.stat().st_size:,} bytes)")
        print(f"  - README.md ({len(DATASET_CARD):,} chars)")
        return

    api = HfApi()
    print(f"Creating dataset repo {args.repo} (private={args.private})...")
    create_repo(args.repo, repo_type="dataset", private=args.private, exist_ok=True)

    print("Uploading dataset card (README.md)...")
    api.upload_file(
        path_or_fileobj=DATASET_CARD.encode("utf-8"),
        path_in_repo="README.md",
        repo_id=args.repo,
        repo_type="dataset",
        commit_message="Add dataset card",
    )

    for p_ in paths:
        print(f"Uploading {p_.name}...")
        api.upload_file(
            path_or_fileobj=str(p_),
            path_in_repo=p_.name,
            repo_id=args.repo,
            repo_type="dataset",
            commit_message=f"Add {p_.name}",
        )

    print()
    print(f"Done. https://huggingface.co/datasets/{args.repo}")


if __name__ == "__main__":
    main()
