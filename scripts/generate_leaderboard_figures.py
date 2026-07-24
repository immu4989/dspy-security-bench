"""Generate the leaderboard's figures from leaderboard/results/*.json.

Everything here is derived from the committed result JSONs, so the figures can
never drift from the board. Regenerate after any new row lands:

    uv run python scripts/generate_leaderboard_figures.py

Outputs (assets/):
  leaderboard_hero.png      ranked bars + 95% CI, colored by bucket
  leaderboard_hero.gif      animated reveal of the same ranking (for social/README)
  within_family_nvidia.png  the airtight comparison: one family, scaled up
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.animation import FuncAnimation, PillowWriter  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "leaderboard/results"
ASSETS = REPO_ROOT / "assets"

# Palette — matches the repo's existing figures (indigo/amber/ink system).
INK = "#0F172A"
INK2 = "#475569"
MUTED = "#6B7280"
GRID = "#E2E8F0"
ROBUST = "#059669"
MIXED = "#F59E0B"
VULN = "#B91C1C"
PROV = "#94A3B8"

BUCKET_COLOR = {"Robust": ROBUST, "Mixed": MIXED, "Vulnerable": VULN}


def load_rows() -> list[dict]:
    rows = []
    for p in sorted(RESULTS_DIR.glob("*.json")):
        r = json.loads(p.read_text())
        if r.get("smoke"):
            continue
        rows.append(r)
    rows.sort(key=lambda r: r["combined_R"], reverse=True)
    return rows


def _color(r: dict) -> str:
    if r["status"] != "confirmed":
        return PROV
    return BUCKET_COLOR.get(r["bucket"], MUTED)


def _style_axes(ax):
    ax.set_xlim(0, 1.06)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"], fontsize=10, color=INK2)
    ax.xaxis.set_ticks_position("none")
    ax.yaxis.set_ticks_position("none")
    for side in ("top", "right", "left", "bottom"):
        ax.spines[side].set_visible(False)
    ax.set_axisbelow(True)
    ax.xaxis.grid(True, color=GRID, linewidth=1)


def _bucket_zones(ax, n):
    """Faint bands + boundary lines so the bucket thresholds are legible."""
    ax.axvspan(0, 0.5, color=VULN, alpha=0.04, zorder=0)
    ax.axvspan(0.5, 0.9, color=MIXED, alpha=0.05, zorder=0)
    ax.axvspan(0.9, 1.0, color=ROBUST, alpha=0.06, zorder=0)
    for x in (0.5, 0.9):
        ax.axvline(x, color=MUTED, linewidth=1, linestyle=(0, (4, 4)), alpha=0.55, zorder=1)
    ax.text(0.25, n - 0.35, "VULNERABLE", ha="center", fontsize=8.5, fontweight="700",
            color=VULN, alpha=0.65)
    ax.text(0.70, n - 0.35, "MIXED", ha="center", fontsize=8.5, fontweight="700",
            color="#B45309", alpha=0.7)
    ax.text(0.95, n - 0.35, "ROBUST", ha="center", fontsize=8.5, fontweight="700",
            color=ROBUST, alpha=0.75)


def hero(rows: list[dict], out: Path) -> None:
    n = len(rows)
    fig, ax = plt.subplots(figsize=(11.5, 0.62 * n + 3.1))
    fig.patch.set_facecolor("white")
    ys = list(range(n))[::-1]

    _bucket_zones(ax, n)
    for y, r in zip(ys, rows, strict=True):
        c = _color(r)
        prov = r["status"] != "confirmed"
        ax.barh(y, r["combined_R"], height=0.58, color=c, zorder=3,
                alpha=0.35 if prov else 1.0,
                edgecolor=c, linewidth=1.6, hatch="//" if prov else None)
        lo, hi = r["combined_ci_low"], r["combined_ci_high"]
        ax.plot([lo, hi], [y, y], color=INK, linewidth=1.6, alpha=0.55, zorder=4)
        for xb in (lo, hi):
            ax.plot([xb, xb], [y - 0.11, y + 0.11], color=INK, linewidth=1.6, alpha=0.55, zorder=4)
        label = f"{r['combined_R'] * 100:.0f}%"
        ax.text(hi + 0.015, y, label, va="center", fontsize=11.5, fontweight="800",
                color=INK if not prov else MUTED, zorder=5)
        if prov:
            ax.text(hi + 0.075, y, "provisional", va="center", fontsize=8.5,
                    color=MUTED, style="italic", zorder=5)

    ax.set_yticks(ys)
    ax.set_yticklabels([f"{r['display_name']}\n{r['family']}" for r in rows],
                       fontsize=10.5, color=INK, linespacing=1.35)
    for t, r in zip(ax.get_yticklabels(), rows, strict=True):
        t.set_fontweight("700" if r["status"] == "confirmed" else "400")
    _style_axes(ax)
    ax.set_ylim(-0.7, n - 0.05)

    fig.suptitle("Which LLMs resist prompt injection?", x=0.012, ha="left",
                 fontsize=19, fontweight="800", color=INK, y=0.985)
    fig.text(0.012, 0.925,
             "Share of injection attacks that FAILED against the base model "
             "(higher is safer). Bars show the 95% CI.",
             fontsize=10.8, color=INK2, ha="left", va="top")

    ax.legend(handles=[
        Patch(facecolor=ROBUST, label="Robust (≥90%)"),
        Patch(facecolor=MIXED, label="Mixed"),
        Patch(facecolor=VULN, label="Vulnerable (<50%)"),
        Patch(facecolor=PROV, alpha=0.35, hatch="//", label="Provisional (CI crosses a boundary)"),
    ], loc="lower right", frameon=False, fontsize=9.2, ncol=2)

    fig.text(0.012, 0.015,
             "AgentDojo `important_instructions` · workspace + banking · frozen task subset · "
             "3 repeats at temperature 0 · dspy.ReActV2, no defense",
             fontsize=8.6, color=MUTED)
    fig.tight_layout(rect=[0, 0.035, 1, 0.90])
    fig.savefig(out, dpi=200, facecolor="white")
    plt.close(fig)
    print(f"wrote {out}")


def hero_gif(rows: list[dict], out: Path) -> None:
    """Animated reveal: bars grow in rank order, then the headline lands."""
    n = len(rows)
    fig, ax = plt.subplots(figsize=(10.5, 0.62 * n + 3.0))
    fig.patch.set_facecolor("white")
    # Fixed margins: ax.clear() runs every frame, so the layout must be set once
    # here (tight_layout per frame would jitter). Left margin fits the longest
    # model label; bottom leaves room for the closing line.
    fig.subplots_adjust(left=0.235, right=0.965, top=0.845, bottom=0.175)
    ys = list(range(n))[::-1]
    FPS, HOLD = 20, 26
    PER = 7  # frames of stagger between bars
    grow = 16
    total = PER * n + grow + HOLD

    def draw(fr):
        ax.clear()
        _bucket_zones(ax, n)
        for i, (y, r) in enumerate(zip(ys, rows, strict=True)):
            t = (fr - i * PER) / grow
            t = max(0.0, min(1.0, t))
            e = 1 - (1 - t) ** 3  # ease-out
            if e <= 0:
                continue
            c = _color(r)
            prov = r["status"] != "confirmed"
            ax.barh(y, r["combined_R"] * e, height=0.58, color=c, zorder=3,
                    alpha=0.35 if prov else 1.0, edgecolor=c, linewidth=1.5,
                    hatch="//" if prov else None)
            if e > 0.98:
                ax.text(r["combined_R"] + 0.015, y, f"{r['combined_R'] * 100:.0f}%",
                        va="center", fontsize=11.5, fontweight="800",
                        color=INK if not prov else MUTED, zorder=5)
        ax.set_yticks(ys)
        ax.set_yticklabels([f"{r['display_name']}\n{r['family']}" for r in rows],
                           fontsize=10, color=INK, linespacing=1.3)
        _style_axes(ax)
        ax.set_ylim(-0.7, n - 0.05)
        ax.set_title("Which LLMs resist prompt injection?\n"
                     "Share of attacks that failed — higher is safer",
                     loc="left", fontsize=13.5, fontweight="800", color=INK, pad=14)
        if fr > total - HOLD:
            # Axes-relative so it sits below the tick labels, never over the bars.
            # Deliberately the decoupling claim, not "bigger = worse": the board
            # does not show a monotonic size/robustness relationship (gpt-oss-20b
            # sits below the 120B Super), and an overclaim here would not survive
            # the next model added.
            ax.text(0.5, -0.165, "Capability does not buy injection-robustness.",
                    transform=ax.transAxes, fontsize=12, fontweight="800",
                    color=VULN, ha="center", va="top")
        return []

    anim = FuncAnimation(fig, draw, frames=total, interval=1000 / FPS, blit=False)
    anim.save(out, writer=PillowWriter(fps=FPS), dpi=95,
              savefig_kwargs={"facecolor": "white"})
    plt.close(fig)
    print(f"wrote {out}")


def within_family(rows: list[dict], out: Path) -> None:
    """The airtight comparison: same vendor, same family, scaled up."""
    by_name = {r["display_name"]: r for r in rows}
    small = by_name.get("Nemotron 3 Nano 30B")
    big = by_name.get("Nemotron 3 Super 120B")
    if not (small and big):
        print("skip within_family (NVIDIA pair not present)")
        return

    fig, ax = plt.subplots(figsize=(9.2, 6.0))
    fig.patch.set_facecolor("white")
    xs = [0, 1]
    vals = [small["combined_R"], big["combined_R"]]
    ax.plot(xs, vals, color=INK, linewidth=2.4, zorder=3, solid_capstyle="round")
    for x, r in zip(xs, (small, big), strict=True):
        ax.scatter([x], [r["combined_R"]], s=340, color=_color(r), zorder=4,
                   edgecolor="white", linewidth=2.5)
        ax.errorbar(x, r["combined_R"],
                    yerr=[[r["combined_R"] - r["combined_ci_low"]],
                          [r["combined_ci_high"] - r["combined_R"]]],
                    color=INK, alpha=0.5, capsize=5, linewidth=1.6, zorder=3)
        ax.text(x, r["combined_R"] + 0.055, f"{r['combined_R'] * 100:.0f}%",
                ha="center", fontsize=17, fontweight="800", color=INK)
        ax.text(x, r["combined_R"] - 0.075, r["bucket"], ha="center", fontsize=10.5,
                fontweight="700", color=_color(r))

    # Drop arrow sits clear to the right of the Super point so it never collides
    # with that point's value label.
    drop = (small["combined_R"] - big["combined_R"]) * 100
    ax_x = 1.20
    ax.plot([1.0, ax_x], [small["combined_R"]] * 2, color=VULN, linewidth=1,
            linestyle=(0, (3, 3)), alpha=0.5, zorder=2)
    ax.annotate("", xy=(ax_x, big["combined_R"]), xytext=(ax_x, small["combined_R"]),
                arrowprops=dict(arrowstyle="-|>", color=VULN, linewidth=2.4, shrinkA=0, shrinkB=0))
    ax.text(ax_x + 0.05, (small["combined_R"] + big["combined_R"]) / 2,
            f"−{drop:.0f}\npoints", fontsize=14, fontweight="800", color=VULN,
            va="center", linespacing=1.25)

    ax.axhspan(0.9, 1.02, color=ROBUST, alpha=0.06)
    ax.axhspan(0.5, 0.9, color=MIXED, alpha=0.05)
    ax.set_xticks(xs)
    ax.set_xticklabels(["Nemotron 3 Nano\n30B parameters", "Nemotron 3 Super\n120B parameters"],
                       fontsize=11.5, color=INK, fontweight="600", linespacing=1.5)
    ax.set_ylim(0.55, 1.06)
    ax.set_xlim(-0.42, 1.68)
    ax.set_yticks([0.6, 0.7, 0.8, 0.9, 1.0])
    ax.set_yticklabels(["60%", "70%", "80%", "90%", "100%"], fontsize=10, color=INK2)
    ax.set_ylabel("Injection-robustness", fontsize=11, color=INK2)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color=GRID, linewidth=1)
    ax.xaxis.set_ticks_position("none")
    ax.yaxis.set_ticks_position("none")

    fig.suptitle("Same family. Same vendor. Scaled up 4×.", x=0.02, ha="left",
                 fontsize=18, fontweight="800", color=INK, y=0.98)
    ax.set_title("The only comparison where nothing else varies — and robustness still falls.",
                 loc="left", fontsize=11, color=INK2, pad=18)
    fig.text(0.02, 0.015, "Same protocol, tasks, attack, and scaffold for both models. "
                          "Error bars are 95% CIs.", fontsize=8.8, color=MUTED)
    fig.tight_layout(rect=[0, 0.03, 1, 0.93])
    fig.savefig(out, dpi=200, facecolor="white")
    plt.close(fig)
    print(f"wrote {out}")


def main() -> None:
    ASSETS.mkdir(exist_ok=True)
    rows = load_rows()
    if not rows:
        raise SystemExit("no result rows found")
    print(f"{len(rows)} rows")
    hero(rows, ASSETS / "leaderboard_hero.png")
    within_family(rows, ASSETS / "within_family_nvidia.png")
    hero_gif(rows, ASSETS / "leaderboard_hero.gif")


if __name__ == "__main__":
    main()
