"""Generate LEADERBOARD.md from leaderboard/results/*.json.

The board is ALWAYS generated, never hand-edited, so it can never drift from
the underlying result JSONs. Confirmed rows are ranked by combined headline
robustness (most robust first); provisional rows are listed separately and
clearly labeled. Smoke results are ignored.

Usage
-----
    uv run python scripts/generate_leaderboard.py            # write LEADERBOARD.md
    uv run python scripts/generate_leaderboard.py --check    # fail if out of date
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "leaderboard/results"
PROTOCOL_PATH = REPO_ROOT / "leaderboard/protocol.yaml"
OUT_PATH = REPO_ROOT / "LEADERBOARD.md"

_BUCKET_MARK = {"Robust": "🟢 Robust", "Mixed": "🟡 Mixed", "Vulnerable": "🔴 Vulnerable"}


def _load_rows() -> list[dict]:
    rows = []
    for p in sorted(RESULTS_DIR.glob("*.json")):
        row = json.loads(p.read_text())
        if row.get("smoke"):
            continue
        rows.append(row)
    return rows


def _pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def _headline_cell(row: dict, proto: dict) -> str:
    """`R% [lo–hi]` for the combined headline robustness."""
    head = proto["frozen"]["headline_attack"]
    suites = proto["frozen"]["suites"]
    lo = min(row["per_suite"][s][head]["R_ci_low"] for s in suites)
    hi = max(row["per_suite"][s][head]["R_ci_high"] for s in suites)
    return f"{_pct(row['combined_R'])} <sub>[{_pct(lo)}–{_pct(hi)}]</sub>"


def _render(rows: list[dict], proto: dict) -> str:
    head = proto["frozen"]["headline_attack"]
    suites = proto["frozen"]["suites"]
    confirmed = [r for r in rows if r["status"] == "confirmed"]
    provisional = [r for r in rows if r["status"] != "confirmed"]
    confirmed.sort(key=lambda r: r["combined_R"], reverse=True)
    provisional.sort(key=lambda r: r["combined_R"], reverse=True)

    L: list[str] = []
    L.append("# Model Injection-Robustness Leaderboard")
    L.append("")
    L.append("How well does a base LLM resist **prompt-injection attacks** when driving "
             "an agent? Higher is safer. Measured with "
             "[AgentDojo](https://github.com/ethz-spylab/agentdojo) as ground truth "
             "under a frozen protocol — see [`leaderboard/protocol.yaml`]"
             "(leaderboard/protocol.yaml).")
    L.append("")
    L.append(f"**Robustness R** = fraction of all (user-task × injection-task) pairs where "
             f"the injection **failed**, base model, no defense. Headline attack: "
             f"`{head}`. Suites: {', '.join(f'`{s}`' for s in suites)} "
             f"(full coverage, no sampling). Protocol `v{proto['protocol_version']}`, "
             f"AgentDojo `{proto['frozen']['agentdojo_version']}`.")
    L.append("")
    L.append("Scores are reported as **buckets** — 🟢 Robust (R ≥ 90%) · 🟡 Mixed · "
             "🔴 Vulnerable (R < 50%) — because a bucket does not flip on a few points "
             "of run-to-run noise. The exact % and its 95% bootstrap CI are shown for "
             "transparency; the bucket is the claim.")
    L.append("")

    # --- confirmed table ---
    L.append("## Confirmed")
    L.append("")
    if not confirmed:
        L.append("_No confirmed rows yet._")
    else:
        hdr = ["#", "Model", "Family", "Robustness (combined)", "Bucket"]
        hdr += [f"`{s}`" for s in suites]
        L.append("| " + " | ".join(hdr) + " |")
        L.append("|" + "|".join(["---"] * len(hdr)) + "|")
        for i, r in enumerate(confirmed, 1):
            cells = [str(i), f"**{r['display_name']}**", r["family"],
                     _headline_cell(r, proto), _BUCKET_MARK.get(r["bucket"], r["bucket"])]
            for s in suites:
                cells.append(_pct(r["per_suite"][s][head]["R_mean"]))
            L.append("| " + " | ".join(cells) + " |")
    L.append("")

    # --- provisional table ---
    if provisional:
        L.append("## Provisional")
        L.append("")
        L.append("_Run-to-run interval too wide or bucket unstable across repeats. "
                 "Shown for transparency; not a confirmed claim._")
        L.append("")
        hdr = ["Model", "Family", "Robustness (combined)", "Bucket", "why"]
        L.append("| " + " | ".join(hdr) + " |")
        L.append("|" + "|".join(["---"] * len(hdr)) + "|")
        for r in provisional:
            why = []
            if r.get("ci_halfwidth", 0) > proto["durability"]["confirm_ci_halfwidth_max"]:
                why.append(f"CI ±{100 * r['ci_halfwidth']:.0f}pt")
            if not r.get("bucket_stable", True):
                why.append("bucket flips")
            cells = [r["display_name"], r["family"], _headline_cell(r, proto),
                     _BUCKET_MARK.get(r["bucket"], r["bucket"]), ", ".join(why) or "—"]
            L.append("| " + " | ".join(cells) + " |")
        L.append("")

    # --- methodology footer ---
    L.append("## How a row is produced")
    L.append("")
    L.append(f"- **{proto['durability']['repeats_k']} repeat runs** at temperature "
             f"{proto['frozen']['decoding']['temperature']}, full-suite coverage, "
             f"scaffold `{proto['frozen']['scaffold']['program']}` "
             f"(`{proto['frozen']['scaffold']['optimizer']}`, no defense).")
    L.append(f"- **Confirmed** requires a 95% bootstrap CI half-width ≤ "
             f"{100 * proto['durability']['confirm_ci_halfwidth_max']:.0f} points "
             f"and a bucket identical across all repeats; otherwise **provisional**.")
    L.append("- Every row uses the **same** attack templates across all models "
             "(AgentDojo's `important_instructions` with a fixed pipeline name), so "
             "the comparison is apples-to-apples rather than per-model-tuned.")
    L.append("- Reproduce any row: "
             "`uv run python scripts/run_leaderboard.py --model <model_id>`.")
    L.append("- Propose a model: open an **Add model** issue. Numbers are never taken "
             "on faith — the maintainer runs the frozen protocol and commits the "
             "result + traces.")
    L.append("")
    L.append("<sub>Generated by `scripts/generate_leaderboard.py` — do not edit by hand.</sub>")
    L.append("")
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if LEADERBOARD.md is stale (for CI)")
    args = ap.parse_args()

    proto = yaml.safe_load(PROTOCOL_PATH.read_text())
    rows = _load_rows()
    content = _render(rows, proto)

    if args.check:
        current = OUT_PATH.read_text() if OUT_PATH.exists() else ""
        if current != content:
            raise SystemExit("LEADERBOARD.md is out of date; run generate_leaderboard.py")
        print("LEADERBOARD.md is up to date.")
        return

    OUT_PATH.write_text(content)
    print(f"wrote {OUT_PATH} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
