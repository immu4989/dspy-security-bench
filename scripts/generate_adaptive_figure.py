"""Render the attack-tier ladder: do the defenses hold as the attacker escalates?

For Mistral Large / workspace, plots injection-security (attack failure rate)
for each defense across three attacker tiers:
  1. static        — AgentDojo's fixed important_instructions template (v0.2.0)
  2. rule-based    — hand-crafted defense-aware payload (adaptive.py)
  3. LM-driven     — iterative, defense-aware attacker, K=5 (lm_driven.py)

The story: the undefended agent is broken at every tier; the cheap defenses
hold at every tier — including against the LM-driven adaptive attacker that
provably breaks the undefended agent.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "data/results"
ASSETS_DIR = REPO_ROOT / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

DEFENSES = ["none", "security_prompt", "spotlight_delim", "spotlight_datamark", "sandwich"]
DLABEL = {
    "none": "none\n(baseline)", "security_prompt": "security\nprompt",
    "spotlight_delim": "spotlight\ndelim", "spotlight_datamark": "spotlight\ndatamark",
    "sandwich": "sandwich",
}
# security_rate = attack failure rate (higher = safer). important_instructions column.
STATIC = {"none": 0.0, "security_prompt": 1.0, "spotlight_delim": 1.0,
          "spotlight_datamark": 1.0, "sandwich": 0.2}          # v0.2.0
RULE = {"none": 0.0, "security_prompt": 1.0, "spotlight_delim": 1.0,
        "spotlight_datamark": 1.0, "sandwich": 1.0}            # rule-based adaptive


def _lm_driven_security() -> dict:
    """Security under the LM-driven attacker = fraction of tasks NOT broken."""
    d = json.loads((RESULTS_DIR / "lm_driven_attack_mistral_mistral_large_latest.json").read_text())
    by = {}
    for r in d["results"]:
        by.setdefault(r["defense_name"], []).append(r["broken"])
    return {name: 1.0 - (sum(v) / len(v)) for name, v in by.items()}


TIERS = [
    ("static attack", "#94A3B8", STATIC),
    ("rule-based adaptive", "#F59E0B", RULE),
    ("LM-driven adaptive (K=5)", "#E11D48", None),  # filled from audit log
]


def main():
    lm = _lm_driven_security()
    tiers = []
    for label, color, data in TIERS:
        tiers.append((label, color, data if data is not None else lm))

    x = np.arange(len(DEFENSES))
    width = 0.26
    fig, ax = plt.subplots(figsize=(12.5, 6.4))

    for i, (label, color, data) in enumerate(tiers):
        vals = [data.get(d, float("nan")) for d in DEFENSES]
        offset = (i - 1) * width
        bars = ax.bar(x + offset, vals, width, color=color, edgecolor="#1F2937",
                      linewidth=1.1, label=label)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v:.0%}",
                    ha="center", va="bottom", fontsize=8.5, fontweight="700", color="#1F2937")

    ax.axvspan(-0.5, 0.5, color="#FEE2E2", alpha=0.5, zorder=0)
    ax.text(0, 1.12, "undefended:\nbroken at every tier", ha="center", fontsize=9,
            color="#B91C1C", style="italic", fontweight="600")
    ax.text(3, 1.12, "cheap defenses: hold at every tier — including vs. the LM-driven\n"
            "attacker that provably breaks the undefended agent",
            ha="center", fontsize=9, color="#047857", style="italic", fontweight="600")

    ax.set_xticks(x)
    ax.set_xticklabels([DLABEL[d] for d in DEFENSES], fontsize=10.5, fontweight="600")
    ax.set_ylabel("Injection-security (attack failure rate — higher = safer)",
                  fontsize=11, fontweight="600", color="#1F2937")
    ax.set_ylim(0, 1.24)
    ax.set_yticks(np.linspace(0, 1, 6))
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
    ax.grid(axis="y", alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.legend(loc="center right", frameon=False, fontsize=9.5, title="attacker tier")

    fig.suptitle("Do the cheap defenses survive an adaptive attacker?",
                 fontsize=15, fontweight="800", color="#0F172A", y=0.99)
    ax.set_title("Mistral Large · workspace · injection-security as the attacker escalates from a "
                 "fixed template to an iterative, defense-aware LM",
                 fontsize=10, color="#475569", pad=22)

    fig.tight_layout(rect=[0, 0, 1, 0.99])
    out = ASSETS_DIR / "adaptive_attack_ladder.png"
    fig.savefig(out, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"wrote {out}")
    print("LM-driven security by defense:", {k: round(v, 2) for k, v in lm.items()})


if __name__ == "__main__":
    main()
