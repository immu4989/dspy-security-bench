"""Render v0.1 benchmark figures from `data/results/workspace_v01_summary.csv`.

Writes two PNGs into `assets/`:
  - `v01_utility_vs_security.png` — grouped bars per (optimizer × attack)
  - `v01_pareto.png` — scatter of utility vs security

Re-run after any new benchmark to refresh the README chart.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
SUMMARY = REPO_ROOT / "data/results/workspace_v01_summary.csv"
ASSETS_DIR = REPO_ROOT / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

# Stable color palette — deliberately distinct so the README chart reads
# at a glance even on a small screen.
PALETTE = {
    "unoptimized": "#94A3B8",        # slate-400 — neutral baseline
    "bootstrap_fewshot": "#3B82F6",  # blue-500
    "miprov2": "#F97316",            # orange-500
}
ATTACK_HATCHES = {
    "direct": "",
    "important_instructions": "//",
}


def _load_summary() -> pd.DataFrame:
    df = pd.read_csv(SUMMARY)
    # Deterministic optimizer order: unoptimized → bootstrap → miprov2
    order = ["unoptimized", "bootstrap_fewshot", "miprov2"]
    df["optimizer"] = pd.Categorical(df["optimizer"], categories=order, ordered=True)
    return df.sort_values(["attack", "optimizer"]).reset_index(drop=True)


def plot_utility_vs_security(df: pd.DataFrame, out_path: Path) -> None:
    """Grouped bars: x = optimizer, two bar pairs per group (direct vs important_instructions)."""
    attacks = ["direct", "important_instructions"]
    optimizers = list(df["optimizer"].cat.categories)
    n_opt = len(optimizers)
    n_attack = len(attacks)

    fig, axes = plt.subplots(1, 2, figsize=(12, 5), sharey=True)
    metric_labels = [("utility_rate", "Utility (task success rate)"),
                     ("security_rate", "Security (attack failure rate)")]

    for ax, (metric, title) in zip(axes, metric_labels):
        x = np.arange(n_opt)
        width = 0.36

        for ai, attack in enumerate(attacks):
            row_lookup = df[df["attack"] == attack].set_index("optimizer")
            values = [row_lookup.loc[opt, metric] for opt in optimizers]
            colors = [PALETTE[opt] for opt in optimizers]
            offset = (ai - 0.5) * width
            bars = ax.bar(
                x + offset, values, width,
                color=colors, edgecolor="#1F2937", linewidth=1.2,
                hatch=ATTACK_HATCHES[attack],
                label=f"{attack}",
            )
            for bar, val in zip(bars, values):
                ax.text(bar.get_x() + bar.get_width() / 2, val + 0.02,
                        f"{val:.0%}", ha="center", va="bottom",
                        fontsize=9, fontweight="600", color="#1F2937")

        ax.set_xticks(x)
        ax.set_xticklabels([o.replace("_", "\n") for o in optimizers], fontsize=10)
        ax.set_ylim(0, 1.18)
        ax.set_yticks(np.linspace(0, 1.0, 6))
        ax.set_yticklabels([f"{int(v*100)}%" for v in np.linspace(0, 1.0, 6)])
        ax.set_title(title, fontsize=12, fontweight="600", color="#0F172A")
        ax.grid(axis="y", alpha=0.25, linestyle="--")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.set_axisbelow(True)
        ax.legend(loc="upper left", frameon=False, fontsize=9, title="attack")

    fig.suptitle(
        "DSPy optimization moves utility up — and security down on stronger attacks",
        fontsize=13, fontweight="700", color="#0F172A", y=1.02,
    )
    fig.tight_layout()
    fig.savefig(out_path, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def plot_pareto(df: pd.DataFrame, out_path: Path) -> None:
    """Pareto-style scatter: one point per (optimizer × attack), with annotations."""
    fig, ax = plt.subplots(figsize=(8, 6.5))

    markers = {"direct": "o", "important_instructions": "^"}
    # Per-point label offsets — keeps overlapping (bootstrap, mipro)
    # `important_instructions` points from colliding on the plot.
    label_offsets = {
        ("unoptimized", "direct"): (12, 8),
        ("unoptimized", "important_instructions"): (12, 8),
        ("bootstrap_fewshot", "direct"): (12, 8),
        ("bootstrap_fewshot", "important_instructions"): (12, 16),
        ("miprov2", "direct"): (12, 8),
        ("miprov2", "important_instructions"): (12, -22),
    }

    for _, row in df.iterrows():
        color = PALETTE[row["optimizer"]]
        marker = markers[row["attack"]]
        x, y = row["utility_rate"], row["security_rate"]
        # Small jitter so overlapping markers are visually distinguishable
        jitter_x = 0.012 if row["optimizer"] == "miprov2" and row["attack"] == "important_instructions" else 0
        ax.scatter(
            x + jitter_x, y, s=300, c=color, marker=marker,
            edgecolors="#1F2937", linewidths=1.6, zorder=3,
        )
        offset = label_offsets.get((row["optimizer"], row["attack"]), (10, 10))
        label = f"{row['optimizer']}\n({row['attack']})"
        ax.annotate(
            label, (x + jitter_x, y),
            textcoords="offset points", xytext=offset,
            fontsize=9, color="#1F2937",
        )

    # Ideal corner
    ax.scatter([1.0], [1.0], s=120, marker="*", c="#10B981",
               edgecolors="#1F2937", linewidths=1.2, zorder=4)
    ax.annotate("ideal", (1.0, 1.0), textcoords="offset points",
                xytext=(-32, -16), fontsize=10, color="#047857", fontweight="700")

    ax.set_xlim(-0.08, 1.15)
    ax.set_ylim(-0.08, 1.15)
    ax.set_xlabel("Utility (task success rate) →", fontsize=11, fontweight="600", color="#1F2937")
    ax.set_ylabel("Security (attack failure rate) →", fontsize=11, fontweight="600", color="#1F2937")
    ax.set_title(
        "Utility vs security trade-off across optimizers (workspace suite, N=5 user × 1 injection)",
        fontsize=11, fontweight="600", color="#0F172A",
    )
    ax.grid(alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)
    ax.axhline(1.0, color="#10B981", alpha=0.3, linewidth=1, linestyle=":")
    ax.axvline(1.0, color="#10B981", alpha=0.3, linewidth=1, linestyle=":")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # Legend for optimizers
    handles = [plt.Line2D([0], [0], marker="s", color="w", markerfacecolor=c,
                          markeredgecolor="#1F2937", markersize=12, label=opt)
               for opt, c in PALETTE.items()]
    handles += [plt.Line2D([0], [0], marker=m, color="w", markerfacecolor="#94A3B8",
                           markeredgecolor="#1F2937", markersize=11, label=a)
                for a, m in markers.items()]
    ax.legend(handles=handles, loc="lower left", frameon=True, fontsize=9, framealpha=0.95)

    fig.tight_layout()
    fig.savefig(out_path, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def main() -> None:
    df = _load_summary()
    plot_utility_vs_security(df, ASSETS_DIR / "v01_utility_vs_security.png")
    plot_pareto(df, ASSETS_DIR / "v01_pareto.png")
    print(f"wrote v01_utility_vs_security.png + v01_pareto.png to {ASSETS_DIR}/")


if __name__ == "__main__":
    main()
