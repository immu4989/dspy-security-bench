"""Render the defense-recovery figure for a given model.

Grouped bars: x = defense (baseline first), y = injection-security, one bar
per attack. Shows the undefended baseline collapsing and cheap defenses
recovering it.

Usage:
    python scripts/generate_defense_figures.py mistral/mistral-large-latest
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "data/results"
ASSETS_DIR = REPO_ROOT / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

DEFENSE_ORDER = ["none", "sandwich", "security_prompt", "spotlight_datamark", "spotlight_delim"]
DEFENSE_LABEL = {
    "none": "none\n(baseline)",
    "sandwich": "sandwich",
    "security_prompt": "security\nprompt",
    "spotlight_datamark": "spotlight\ndatamark",
    "spotlight_delim": "spotlight\ndelimiting",
}
ATTACK_STYLE = {
    "direct": ("#059669", "direct attack"),
    "important_instructions": ("#E11D48", "important_instructions (harder)"),
}


def _slug(model_str: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", model_str.lower()).strip("_")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("model")
    p.add_argument("--title-model", default=None, help="display name (default: derived)")
    args = p.parse_args()

    slug = _slug(args.model)
    summary = pd.read_csv(RESULTS_DIR / f"workspace_defense_{slug}_summary.csv")
    title_model = args.title_model or args.model.split("/")[-1]

    defenses = [d for d in DEFENSE_ORDER if d in set(summary["defense"])]
    x = np.arange(len(defenses))
    width = 0.38

    fig, ax = plt.subplots(figsize=(12, 6.3))

    for i, (attack, (color, disp)) in enumerate(ATTACK_STYLE.items()):
        vals = []
        for d in defenses:
            row = summary[(summary["defense"] == d) & (summary["attack"] == attack)]
            vals.append(float(row["security_rate"].iloc[0]) if not row.empty else 0.0)
        offset = (i - 0.5) * width
        bars = ax.bar(x + offset, vals, width, color=color, edgecolor="#1F2937",
                      linewidth=1.2, label=disp)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, v + 0.015, f"{v:.0%}",
                    ha="center", va="bottom", fontsize=10, fontweight="700", color="#1F2937")

    # Shade the baseline column to make the "before" state obvious
    ax.axvspan(-0.5, 0.5, color="#FEE2E2", alpha=0.5, zorder=0)
    ax.text(0, 1.13, "undefended", ha="center", fontsize=9.5, color="#B91C1C",
            style="italic", fontweight="600")
    ax.text(2.5, 1.13, "with a deployable defense", ha="center", fontsize=9.5,
            color="#047857", style="italic", fontweight="600")

    ax.set_xticks(x)
    ax.set_xticklabels([DEFENSE_LABEL[d] for d in defenses], fontsize=10.5, fontweight="600")
    ax.set_ylabel("Injection-security (attack failure rate — higher = safer)",
                  fontsize=11, fontweight="600", color="#1F2937")
    ax.set_ylim(0, 1.22)
    ax.set_yticks(np.linspace(0, 1.0, 6))
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
    ax.grid(axis="y", alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="lower right", frameon=False, fontsize=10)

    fig.suptitle(
        f"Cheap defenses recover {title_model}'s collapsed injection-security",
        fontsize=15, fontweight="800", color="#0F172A", y=0.99,
    )
    ax.set_title(
        "Undefended, the model follows injected instructions ~100% of the time. "
        "A 4-sentence security system prompt fully patches it.",
        fontsize=10.5, color="#475569", pad=26,
    )

    fig.tight_layout(rect=[0, 0, 1, 0.99])
    out = ASSETS_DIR / f"defense_recovery_{slug}.png"
    fig.savefig(out, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
