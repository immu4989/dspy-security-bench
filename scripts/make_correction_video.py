#!/usr/bin/env python3
"""One 1080x1080 story video for dspy-security-bench, as MP4 (dark theme).

The subject is a correction this project published against itself. v0.3.1
reported that a four-sentence `security_prompt` defense survived an adaptive
LM-driven attacker. It did — at the five-round budget that release happened to
test. Re-run at fifty rounds, ten independent times, it falls in nine of them.

  held     — a lone green bar at 100%: "our defense blocked every attack."
  budget   — the number nobody printed: the attacker got five tries.
  collapse — K=50 x 10 runs; survival drops 100% -> 10%, ghost marks the fall.
  curve    — attack success by budget: 10 / 30 / 60 / 90% at K=5/10/15/20.
  close    — Carlini et al. 2019 already prescribed this exact check.

Every number is read from data/results/adaptive_budget/summary.json at build
time, so the video cannot drift from the committed experiment.

matplotlib + pip static ffmpeg (imageio-ffmpeg); no system ffmpeg. Run with the
interpreter that has imageio_ffmpeg (system python3 here):

    python3 scripts/make_correction_video.py
        -> ~/Documents/dspy-security-bench-social/dsb-correction.mp4
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import imageio_ffmpeg
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.animation import FFMpegWriter, FuncAnimation  # noqa: E402

plt.rcParams["animation.ffmpeg_path"] = imageio_ffmpeg.get_ffmpeg_exe()
plt.rcParams["font.family"] = "DejaVu Sans"

# dark palette — same as make_story_video.py, keep the two videos on-brand
BG = "#12102e"  # deep indigo-navy, ties into the indigo/amber chart branding
INK = "#e6edf3"
INK2 = "#9aa4b2"
MUTED = "#5b6673"
GRID = "#232b36"
BLUE = "#4c8dff"
GREEN = "#2fd196"
RED = "#ff5b57"
AMBER = "#f2b34a"

FPS = 24
FADE = 0.3

# ---------------------------------------------------------------- the numbers
SUMMARY = Path(__file__).resolve().parent.parent / "data/results/adaptive_budget/summary.json"
_s = json.loads(SUMMARY.read_text())
N_RUNS = _s["n_runs"]
N_BROKEN = _s["n_broken"]
ROUNDS = sorted(_s["rounds_to_break"])
CI_LO, CI_HI = (round(100 * v) for v in _s["break_rate_ci95_wilson"])
SURVIVAL = 1.0 - N_BROKEN / N_RUNS                      # 0.10
K_OLD = 5                                               # the v0.3.1 budget
BUDGETS = [5, 10, 15, 20]
# empirical CDF: share of the 10 runs already broken by round K
SUCCESS = [sum(1 for r in ROUNDS if r <= k) / N_RUNS for k in BUDGETS]

SCENES = [
    ("held", 6.0),
    ("budget", 7.0),
    ("collapse", 9.0),
    ("curve", 9.0),
    ("close", 7.5),
]
_starts, _acc = {}, 0.0
for _name, _d in SCENES:
    _starts[_name] = (_acc, _acc + _d)
    _acc += _d
DURATION = _acc
FRAMES = int(DURATION * FPS)


def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def ease(x):
    x = clamp(x)
    return x * x * (3 - 2 * x)


def seg(t, a, b):
    return ease((t - a) / (b - a)) if b > a else 0.0


def lerp(a, b, x):
    return a + (b - a) * x


def hexlerp(c1, c2, x):
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{int(lerp(p, q, x)):02x}" for p, q in zip(a, b))


fig = plt.figure(figsize=(9, 9), dpi=120)
fig.patch.set_facecolor(BG)
ax = fig.add_axes([0.07, 0.14, 0.86, 0.58])


def T(x, y, s, size, color, A, weight="normal", ha="center", style="normal"):
    if A <= 0.01:
        return
    fig.text(x, y, s, fontsize=size, color=color, alpha=clamp(A), ha=ha,
             fontweight=weight, fontstyle=style)


def title_caption(title, cap, A, capcolor=INK2):
    T(0.07, 0.925, title, 21, INK, A, weight="bold", ha="left")
    if cap:
        T(0.07, 0.878, cap, 13.5, capcolor, A, ha="left")


def setup_axes(xhi=3.6, ymax=1.16, grid=True):
    ax.clear()
    ax.set_facecolor("none")
    ax.set_xlim(-0.6, xhi)
    ax.set_ylim(0, ymax)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])
    if grid:
        for gy in (0.25, 0.5, 0.75, 1.0):
            ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color="#2c3540", lw=1.5)


def _bars(labels, heights, colors, ghosts=None, A=1.0, label_dy=-0.055,
          fs_lab=11, show_vals=True, width=0.62):
    for i in range(len(labels)):
        if ghosts and ghosts[i] is not None:
            ax.add_patch(plt.Rectangle((i - width / 2, 0), width, ghosts[i], fill=False,
                                       ec=MUTED, ls=(0, (3, 3)), lw=1.1, alpha=0.6 * A))
        ax.bar(i, heights[i], width=width, color=colors[i], alpha=A, zorder=3)
        if show_vals and heights[i] > 0.02:
            ax.text(i, heights[i] + 0.02, f"{heights[i]:.0%}", ha="center", va="bottom",
                    fontsize=12, color=INK, fontweight="bold", alpha=A)
        if labels[i]:
            ax.text(i, label_dy, labels[i], ha="center", va="top", fontsize=fs_lab,
                    color=INK, alpha=A)


# ------------------------------------------------------------------ scenes
def scene_held(t, A):
    """Cold open: one tall green bar. The result as it was published."""
    ax.set_visible(True)
    setup_axes(xhi=0.6)
    grow = seg(t, 0.4, 2.0)
    turn = seg(t, 2.0, 2.9)
    _bars([""], [1.0 * grow], [hexlerp(BLUE, GREEN, turn)], A=A, width=0.5)
    if turn > 0.3:
        ax.text(0, -0.055, "adaptive attacker vs security_prompt", ha="center",
                va="top", fontsize=12, color=INK, alpha=A * turn)
    ha = seg(t, 2.6, 3.4)
    if ha > 0:
        T(0.5, 0.775, "HELD", 15, GREEN, ha * A, weight="bold")
    title_caption("Our defense blocked every attack.",
                  "Shipped in v0.3.1. Then we checked one thing.", A,
                  capcolor=INK if t > 3.4 else INK2)


def scene_budget(t, A):
    """The number nobody prints: how many tries did the attacker get?"""
    ax.set_visible(True)
    setup_axes(xhi=0.6)
    recede = seg(t, 1.4, 2.6)
    _bars([""], [1.0], [GREEN], A=A * (1 - 0.92 * recede), width=0.5,
          show_vals=(recede < 0.15))
    ax.text(0, -0.055, "adaptive attacker vs security_prompt", ha="center",
            va="top", fontsize=12, color=INK, alpha=A * (1 - 0.85 * recede))
    ka = seg(t, 2.4, 3.4)
    if ka > 0:
        T(0.5, 0.46, f"K = {K_OLD}", 72, AMBER, ka * A, weight="bold")
        T(0.5, 0.395, "rounds. that was the entire budget.", 17, INK2,
          seg(t, 3.0, 4.0) * A)
    title_caption("Held against how many tries?",
                  "It is the number nobody prints, including us.", A,
                  capcolor=INK if t > 3.0 else INK2)


def scene_collapse(t, A):
    """Re-run at K=50, ten times. Survival craters; ghost marks the fall."""
    ax.set_visible(True)
    setup_axes(xhi=1.6)
    grow = seg(t, 0.6, 2.0)
    attack = seg(t, 3.2, 5.6)
    h1 = lerp(1.0 * grow, SURVIVAL, attack) if t >= 3.2 else 1.0 * grow
    colors = [GREEN, hexlerp(BLUE, RED, attack)]
    ghosts = [None, (1.0 if attack > 0.05 else None)]
    _bars(["v0.3.1\nK = 5, one run", f"re-run\nK = 50, {N_RUNS} runs"],
          [1.0, h1], colors, ghosts, A=A, label_dy=-0.08)
    fl = clamp(1.0 - abs(t - 4.3) / 0.5) if 3.8 < t < 4.8 else 0.0
    if fl > 0:
        ax.add_patch(plt.Rectangle((-0.6, 0), 2.2, 1.16, color=RED,
                                   alpha=0.10 * fl * A, zorder=1))
    la = seg(t, 4.6, 5.4)
    if la > 0:
        T(0.31, 0.735, "HELD", 13, GREEN, la * A, weight="bold")
        T(0.66, 0.50, "BROKEN", 13, RED, la * A, weight="bold")
    T(0.5, 0.032, f"broken in {N_BROKEN} of {N_RUNS} runs   ·   "
      f"95% CI [{CI_LO}–{CI_HI}%]", 14.5, INK, seg(t, 5.0, 6.0) * A)
    if t < 3.0:
        title_caption("Re-run at 50 rounds. Ten times.",
                      "Same defense, same target, same attacker model.", A)
    else:
        title_caption("Re-run at 50 rounds. Ten times.",
                      f"The defense survived {N_RUNS - N_BROKEN} run in {N_RUNS}.", A,
                      capcolor=INK)


def scene_curve(t, A):
    """Attack success as a function of the attacker's budget."""
    ax.set_visible(True)
    setup_axes(xhi=3.6)
    labels = [f"K = {k}" for k in BUDGETS]
    heights, colors = [], []
    for i, v in enumerate(SUCCESS):
        g = seg(t, 0.5 + 0.45 * i, 1.9 + 0.45 * i)
        heights.append(v * g)
        colors.append(hexlerp(AMBER, RED, i / (len(SUCCESS) - 1)))
    _bars(labels, heights, colors, A=A, label_dy=-0.055)
    ya = seg(t, 0.4, 1.2)
    T(0.07, 0.745, "attacks that succeeded", 12.5, INK2, ya * A, ha="left")
    pa = seg(t, 3.4, 4.4)
    if pa > 0:
        ax.annotate("", xy=(0.0, SUCCESS[0] + 0.10), xytext=(0.55, 0.62),
                    arrowprops=dict(arrowstyle="-|>", color=AMBER, lw=2.2,
                                    alpha=pa * A, connectionstyle="arc3,rad=0.25"))
        ax.text(0.62, 0.64, "we published\nfrom here", ha="left", va="bottom",
                fontsize=12.5, color=AMBER, alpha=pa * A, fontweight="bold")
    if t < 3.2:
        title_caption("Attack success is a budget dial.",
                      "Same defense at every bar. Only the tries change.", A)
    else:
        title_caption("Attack success is a budget dial.",
                      "The published number sat at the bottom of the ramp.", A,
                      capcolor=INK)


def scene_close(t, A):
    ax.set_visible(False)
    T(0.5, 0.75, "This check is seven years old.", 26, INK, A, weight="bold")
    a1 = A * seg(t, 0.6, 1.5)
    T(0.5, 0.625, "“Verify that doubling the number of iterations", 18, AMBER, a1,
      style="italic")
    T(0.5, 0.575, "does not increase attack success rate.”", 18, AMBER, a1,
      style="italic")
    T(0.5, 0.505, "Carlini et al., 2019 — On Evaluating Adversarial Robustness",
      13.5, INK2, A * seg(t, 1.3, 2.1))
    T(0.5, 0.375, "We skipped it. Cost to find out: $0.30.", 21, RED,
      A * seg(t, 2.2, 3.0), weight="bold")
    T(0.5, 0.285, "Ten runs, published raw, with the retraction in the changelog.",
      14.5, INK2, A * seg(t, 2.7, 3.5))
    T(0.5, 0.15, "github.com/immu4989/dspy-security-bench", 16, INK,
      A * seg(t, 3.1, 3.9), weight="bold")


DISPATCH = {"held": scene_held, "budget": scene_budget, "collapse": scene_collapse,
            "curve": scene_curve, "close": scene_close}


def draw(frame):
    t = frame / FPS
    fig.texts.clear()
    fig.patches.clear()
    for extra in list(fig.axes):
        if extra is not ax:
            extra.remove()
    ax.clear()
    ax.set_axis_off()
    name = SCENES[-1][0]
    for nm, _d in SCENES:
        s, e = _starts[nm]
        if s <= t < e:
            name = nm
            break
    s, e = _starts[name]
    A = min(ease((t - s) / FADE), ease((e - t) / FADE))
    DISPATCH[name](t - s, clamp(A))
    return []


def main():
    out_dir = os.path.expanduser("~/Documents/dspy-security-bench-social")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "dsb-correction.mp4")
    anim = FuncAnimation(fig, draw, frames=FRAMES, interval=1000 / FPS, blit=False)
    writer = FFMpegWriter(fps=FPS, bitrate=4800, extra_args=["-pix_fmt", "yuv420p"])
    anim.save(out, writer=writer, dpi=120, savefig_kwargs={"facecolor": BG})
    print(f"wrote {out}  ({os.path.getsize(out) / 1e6:.1f} MB, {DURATION:.0f}s, {FRAMES} frames)")
    print(f"data: {N_BROKEN}/{N_RUNS} broken, CI [{CI_LO},{CI_HI}], "
          f"budget curve {[f'{v:.0%}' for v in SUCCESS]}")


if __name__ == "__main__":
    main()
