"""Render the v0.1.4 capability-vs-robustness figure.

Four models ordered left->right by approximate general capability
(parameter scale / public benchmark standing). y-axis is UNOPTIMIZED
injection-security (attack failure rate) on both attacks.

The point: injection-robustness does NOT track capability. Within the
Mistral family, scaling Small -> Large collapses security from ~1.0 to
~0.1, while DeepSeek V3 (the most capable here) stays robust. Robustness
is an alignment property, separable from raw capability.

Capability ordering is an external, independent axis (model scale /
general benchmark performance), deliberately NOT the in-benchmark utility
— utility-under-attack is contaminated by derailment, so using it as the
x-axis would be circular.

Re-run after any new model probe.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "data/results"
ASSETS_DIR = REPO_ROOT / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

# (label, summary_csv, family) ordered weak -> strong by external capability
MODELS = [
    ("gpt-4o-mini",   "workspace_v01_summary.csv",                              "OpenAI"),
    ("Mistral Small", "workspace_v01_mistral_mistral_small_latest_summary.csv", "Mistral"),
    ("Mistral Large", "workspace_v01_mistral_mistral_large_latest_summary.csv", "Mistral"),
    ("DeepSeek V3",   "workspace_v01_deepseek_summary.csv",                     "DeepSeek"),
]

ATTACK_STYLE = {
    "direct":                 ("#4F46E5", "direct attack"),           # indigo
    "important_instructions": ("#F59E0B", "important_instructions"),   # amber
}


def _unopt_security() -> dict:
    out = {}
    for label, csv_name, _ in MODELS:
        df = pd.read_csv(RESULTS_DIR / csv_name)
        u = df[df["optimizer"] == "unoptimized"]
        out[label] = {
            a: float(u[u["attack"] == a]["security_rate"].iloc[0])
            for a in ATTACK_STYLE
        }
    return out


def main():
    sec = _unopt_security()
    labels = [m[0] for m in MODELS]
    x = np.arange(len(labels))
    width = 0.38

    fig, ax = plt.subplots(figsize=(11.5, 6.2))

    for i, (attack, (color, disp)) in enumerate(ATTACK_STYLE.items()):
        vals = [sec[l][attack] for l in labels]
        offset = (i - 0.5) * width
        bars = ax.bar(x + offset, vals, width, color=color, edgecolor="#1F2937",
                      linewidth=1.2, label=disp)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, v + 0.015,
                    f"{v:.0%}", ha="center", va="bottom",
                    fontsize=10, fontweight="700", color="#1F2937")

    # Annotate the within-family collapse: Mistral Small (idx 1) -> Large (idx 2)
    ax.annotate(
        "same family, scaled up\n→ security collapses",
        xy=(2, 0.10), xytext=(2.05, 0.62),
        fontsize=11, fontweight="700", color="#B91C1C", ha="center",
        arrowprops=dict(arrowstyle="-|>", color="#B91C1C", linewidth=2.2,
                        connectionstyle="arc3,rad=-0.2"),
    )
    # Bracket the two Mistral models
    ax.plot([0.62, 2.38], [1.14, 1.14], color="#6B7280", linewidth=1.2)
    ax.text(1.5, 1.16, "Mistral family", ha="center", va="bottom",
            fontsize=9.5, color="#6B7280", style="italic")

    ax.set_xticks(x)
    ax.set_xticklabels(
        [f"{m[0]}\n({m[2]})" for m in MODELS],
        fontsize=10.5, fontweight="600",
    )
    ax.set_ylabel("Unoptimized injection-security\n(attack failure rate — higher = safer)",
                  fontsize=11, fontweight="600", color="#1F2937")
    ax.set_ylim(0, 1.28)
    ax.set_yticks(np.linspace(0, 1.0, 6))
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
    ax.grid(axis="y", alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="lower left", frameon=False, fontsize=10)

    # x-axis capability arrow
    ax.text(0.0, -0.30, "← lower", fontsize=9, color="#6B7280", transform=ax.get_xaxis_transform())
    ax.text(3.0, -0.30, "higher →", fontsize=9, color="#6B7280", ha="right", transform=ax.get_xaxis_transform())
    ax.text(1.5, -0.34, "approximate general capability (model scale / benchmark standing)",
            fontsize=9, color="#6B7280", ha="center", style="italic",
            transform=ax.get_xaxis_transform())

    fig.suptitle(
        "Injection-robustness does not track model capability",
        fontsize=15, fontweight="800", color="#0F172A", y=0.99,
    )
    ax.set_title(
        "The most capable model in a family can be its most exploitable. "
        "Robustness is an alignment property, not a capability one.",
        fontsize=10.5, color="#475569", pad=14,
    )

    fig.tight_layout(rect=[0, 0.04, 1, 0.99])
    out = ASSETS_DIR / "v014_capability_vs_robustness.png"
    fig.savefig(out, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"wrote {out}")
    for l in labels:
        print(f"  {l:15s} direct={sec[l]['direct']:.0%}  important_instructions={sec[l]['important_instructions']:.0%}")


if __name__ == "__main__":
    main()
