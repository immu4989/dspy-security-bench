"""Build the website's compact data payload from committed leaderboard results.

The website never owns benchmark numbers. This generator extracts the public
presentation fields from ``leaderboard/results/*.json`` so the interactive
experience and ``LEADERBOARD.md`` remain views over the same evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "leaderboard/results"
DEFAULT_OUT = ROOT / "site/data.json"
GITHUB = "https://github.com/immu4989/dspy-security-bench/blob/main"


def build_payload(results_dir: Path = RESULTS_DIR) -> dict:
    models = []
    protocol_versions = set()
    for path in sorted(results_dir.glob("*.json")):
        row = json.loads(path.read_text())
        if row.get("smoke"):
            continue
        protocol_versions.add(row["protocol_version"])
        suites = {}
        for suite_name, attacks in row.get("per_suite", {}).items():
            primary = attacks.get("important_instructions") or next(iter(attacks.values()))
            suites[suite_name] = {
                "robustness": primary["R_mean"],
                "capability": primary["U_mean"],
            }
        models.append({
            "name": row["display_name"],
            "family": row["family"],
            "modelId": row["model_id"],
            "robustness": row["combined_R"],
            "ciLow": row["combined_ci_low"],
            "ciHigh": row["combined_ci_high"],
            "capability": row["combined_U"],
            "bucket": row["bucket"],
            "status": row["status"],
            "classification": row["bucket"] if row["status"] == "confirmed" else "Provisional",
            "pairs": sum(
                attack.get("n_pairs_unique", attack.get("n_pairs", 0))
                for attacks in row.get("per_suite", {}).values()
                for attack in attacks.values()
            ),
            "suites": suites,
            "result": f"{GITHUB}/leaderboard/results/{path.name}",
        })
    models.sort(key=lambda model: (-model["robustness"], -model["capability"], model["name"]))
    families = sorted({model["family"] for model in models})
    return {
        "protocol": ", ".join(sorted(protocol_versions)),
        "modelCount": len(models),
        "familyCount": len(families),
        "families": families,
        "models": models,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    payload = build_payload()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {args.out} ({payload['modelCount']} models)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
