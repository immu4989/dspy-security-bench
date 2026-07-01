"""Render the v0.1.3 three-regime comparison chart.

Loads all three model summaries and produces `assets/v013_three_regime.png`
— a two-panel view of utility_delta and security_delta (vs unoptimized
baseline) per (model, optimizer) on the `important_instructions` attack.

Emphasizes the three-regime story: both the utility benefit AND the
security cost of prompt optimization decrease as base-model capability
increases.

Re-run after any new provider probe to refresh the chart.
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

# Ordered weak → strong by unoptimized workspace utility on `direct`:
# gpt-4o-mini 0.00, Mistral Small 0.20, DeepSeek V3 0.80
MODELS = [
    ("gpt-4o-mini",   "workspace_v01_summary.csv",                                  "weak"),
    ("Mistral Small", "workspace_v01_mistral_mistral_small_latest_summary.csv",     "mid"),
    ("DeepSeek V3",   "workspace_v01_deepseek_summary.csv",                         "strong"),
]

PALETTE = {
    "bootstrap_fewshot": "#059669",  # emerald-600
    "miprov2":           "#E11D48",  # rose-600
}
OPT_DISPLAY = {"bootstrap_fewshot": "BootstrapFewShot", "miprov2": "MIPROv2"}

ATTACK = "important_instructions"


def _load_deltas() -> pd.DataFrame:
    """(model, optimizer, utility_delta, security_delta) for the harder attack."""
    rows = []
    for model_name, csv_name, regime in MODELS:
        df = pd.read_csv(RESULTS_DIR / csv_name)
        df = df[df["attack"] == ATTACK]
        unopt = df[df["optimizer"] == "unoptimized"].iloc[0]
        for opt in ("bootstrap_fewshot", "miprov2"):
            row = df[df["optimizer"] == opt].iloc[0]
            rows.append({
                "model": model_name,
                "regime": regime,
                "optimizer": opt,
                "utility_delta": row["utility_rate"] - unopt["utility_rate"],
                "security_delta": row["security_rate"] - unopt["security_rate"],
            })
    return pd.DataFrame(rows)


def _plot_delta_panel(ax, deltas: pd.DataFrame, metric: str, title: str,
                      ylabel: str, ymin: float, ymax: float):
    model_names = [m[0] for m in MODELS]
    x = np.arange(len(model_names))
    width = 0.35

    for i, opt in enumerate(("bootstrap_fewshot", "miprov2")):
        opt_data = deltas[deltas["optimizer"] == opt]
        values = [opt_data[opt_data["model"] == m][metric].iloc[0] for m in model_names]
        offset = (i - 0.5) * width
        bars = ax.bar(
            x + offset, values, width,
            color=PALETTE[opt], edgecolor="#1F2937", linewidth=1.2,
            label=OPT_DISPLAY[opt],
        )
        for bar, val in zip(bars, values):
            if abs(val) < 0.001:
                label = " 0"
                y = 0.015
                va = "bottom"
            else:
                label = f"{val*100:+.0f}pp"
                y = val + (0.012 if val >= 0 else -0.012)
                va = "bottom" if val >= 0 else "top"
            ax.text(bar.get_x() + bar.get_width() / 2, y, label,
                    ha="center", va=va, fontsize=10, fontweight="700", color="#1F2937")

    ax.axhline(0, color="#1F2937", linewidth=0.9)
    ax.set_xticks(x)
    ax.set_xticklabels(
        [f"{m}\n({r})" for m, _, r in MODELS],
        fontsize=11, fontweight="600",
    )
    ax.set_ylabel(ylabel, fontsize=11, fontweight="600", color="#1F2937")
    ax.set_title(title, fontsize=12, fontweight="700", color="#0F172A", pad=10)
    ax.set_ylim(ymin, ymax)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v*100:+.0f}pp"))
    ax.grid(axis="y", alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(loc="upper right", frameon=False, fontsize=9)


def main():
    deltas = _load_deltas()
    print("computed deltas:")
    print(deltas.to_string(index=False))

    fig, axes = plt.subplots(1, 2, figsize=(13.5, 5.5))

    _plot_delta_panel(
        axes[0], deltas, metric="utility_delta",
        title="Optimization → utility change",
        ylabel="Δ task success rate (percentage points)",
        ymin=-0.10, ymax=0.55,
    )
    _plot_delta_panel(
        axes[1], deltas, metric="security_delta",
        title="Optimization → security change",
        ylabel="Δ attack failure rate (percentage points)",
        ymin=-0.30, ymax=0.20,
    )

    fig.suptitle(
        "Three regimes: as base-model capability increases,\n"
        "both the utility benefit AND security cost of prompt optimization decrease",
        fontsize=13.5, fontweight="700", color="#0F172A", y=1.02,
    )
    fig.text(
        0.5, -0.03,
        f"workspace suite, N=5 per cell, harder attack ({ATTACK}); "
        "positive = optimization improved that axis, negative = optimization hurt it",
        ha="center", fontsize=9.5, color="#475569", style="italic",
    )

    fig.tight_layout()
    out = ASSETS_DIR / "v013_three_regime.png"
    fig.savefig(out, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
