#!/usr/bin/env python3
"""One 1080x1080 story video for dspy-security-bench, as MP4 (dark theme).

Spine (house grammar): every result looked fine, then the honest check made it
collapse. Cold-opens on a mystery: four agents look safe, one craters.

  Teaser — four unlabeled bars rise, a scan sweeps, ONE collapses to 0 in red.
           "One of these agents just obeyed an attacker. Which one?"
  Act 1  — capability: label them; the more capable Mistral is the one that
           collapsed (Small 100% -> Large 0%, within one family).
  Act 2  — the fix: undefended 0% -> a 4-sentence security prompt restores 100%.
  Act 3  — honest check: an adaptive attacker; the simple defense HELD (100%),
           the clever marker defense FELL (67%).
  Close  — "You can't tell by looking. Scan yours." + repo link.

matplotlib + pip static ffmpeg (imageio-ffmpeg); no system ffmpeg. Run with the
interpreter that has imageio_ffmpeg (system python3 here):

    python3 scripts/make_story_video.py  ->  ~/Documents/dspy-security-bench-social/dsb-story.mp4
"""
from __future__ import annotations

import os

import imageio_ffmpeg
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.animation import FFMpegWriter, FuncAnimation  # noqa: E402

plt.rcParams["animation.ffmpeg_path"] = imageio_ffmpeg.get_ffmpeg_exe()
plt.rcParams["font.family"] = "DejaVu Sans"

# dark palette
BG = "#0d1117"
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

SCENES = [
    ("teaser", 5.0),
    ("cap", 8.0),
    ("fix", 7.5),
    ("adapt", 8.5),
    ("close", 6.5),
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


def _bars(labels, heights, colors, ghosts=None, A=1.0, label_dy=-0.055, fs_lab=11, show_vals=True):
    for i in range(len(labels)):
        if ghosts and ghosts[i] is not None:
            ax.add_patch(plt.Rectangle((i - 0.31, 0), 0.62, ghosts[i], fill=False,
                                       ec=MUTED, ls=(0, (3, 3)), lw=1.1, alpha=0.6 * A))
        ax.bar(i, heights[i], width=0.62, color=colors[i], alpha=A, zorder=3)
        if show_vals:
            if heights[i] > 0.02:
                ax.text(i, heights[i] + 0.02, f"{heights[i]:.0%}", ha="center", va="bottom",
                        fontsize=12, color=INK, fontweight="bold", alpha=A)
            else:
                ax.text(i, 0.02, "0%", ha="center", va="bottom",
                        fontsize=12, color=RED, fontweight="bold", alpha=A)
        if labels[i]:
            ax.text(i, label_dy, labels[i], ha="center", va="top", fontsize=fs_lab,
                    color=INK, alpha=A)


# ------------------------------------------------------------------ scenes
def scene_teaser(t, A):
    ax.set_visible(True)
    setup_axes(xhi=3.6)
    n = 4
    grow = seg(t, 0.3, 1.6)
    collapse = seg(t, 2.9, 3.6)          # bar idx 2 craters
    heights, colors = [], []
    for i in range(n):
        if i == 2:
            h = lerp(1.0, 0.0, collapse) * grow if t < 2.9 else lerp(1.0, 0.0, collapse)
            heights.append(1.0 * grow if t < 2.9 else lerp(1.0, 0.0, collapse))
            colors.append(hexlerp(BLUE, RED, collapse))
        else:
            heights.append(1.0 * grow)
            colors.append(BLUE)
    ghosts = [None, None, (1.0 if collapse > 0.05 else None), None]
    _bars(["", "", "", ""], heights, colors, ghosts, A=A, show_vals=False)
    if heights[2] < 0.05 and collapse > 0.6:
        ax.text(2, 0.02, "0%", ha="center", va="bottom", fontsize=13, color=RED,
                fontweight="bold", alpha=A)
    # scan sweep
    sc = seg(t, 1.6, 2.7)
    if 0 < sc < 1 and t < 2.9:
        xline = lerp(-0.5, 3.5, sc)
        ax.axvline(xline, color=GREEN, lw=2, alpha=0.7 * A)
        T(0.5, 0.80, "scanning for prompt injection…", 15, GREEN, A * seg(t, 1.6, 2.0), style="italic")
    # red flash on collapse
    fl = clamp(1.0 - abs(t - 3.1) / 0.4) if 2.7 < t < 3.5 else 0.0
    if fl > 0:
        ax.add_patch(plt.Rectangle((-0.6, 0), 4.2, 1.16, color=RED, alpha=0.10 * fl * A, zorder=1))
    # setup line during grow, fades out before the hook
    setupA = A * seg(t, 0.2, 0.8) * (1 - seg(t, 2.3, 2.9))
    T(0.5, 0.90, "Four AI agents. All look safe.", 20, INK, setupA, weight="bold")
    # hook text (top), after the collapse
    if t >= 3.4:
        a = A * ease((t - 3.4) / 0.45)
        T(0.5, 0.915, "One of them just obeyed an attacker.", 21, INK, a, weight="bold")
        T(0.5, 0.870, "Same vendor. Same benchmarks. Which one?", 15, INK2, a)


def scene_cap(t, A):
    ax.set_visible(True)
    setup_axes(xhi=3.6)
    labels = ["gpt-4o-mini", "Mistral\nSmall", "Mistral\nLarge", "DeepSeek V3"]
    real = [0.80, 1.00, 0.00, 0.80]
    grow = seg(t, 0.3, 1.6)
    reveal = seg(t, 2.6, 4.4)
    heights = [real[i] * grow for i in range(4)]
    colors = []
    for i in range(4):
        final = RED if real[i] < 0.3 else GREEN
        colors.append(hexlerp(BLUE, final, reveal) if t >= 2.6 else BLUE)
    ghosts = [None, None, (1.0 if reveal > 0.05 else None), None]
    _bars(labels, heights, colors, ghosts, A=A)
    ba = seg(t, 2.6, 3.6)
    if ba > 0:
        ax.plot([0.62, 2.38], [1.10, 1.10], color=MUTED, lw=1.2, alpha=ba * A)
        ax.text(1.5, 1.115, "same family", ha="center", va="bottom", fontsize=11,
                style="italic", color=INK2, alpha=ba * A)
    if t < 2.4:
        title_caption("It's the more capable one.",
                      "Injection-security across four models.", A)
    else:
        title_caption("It's the more capable one.",
                      "Scale up within a family and it collapses to zero.", A, capcolor=INK)


def scene_fix(t, A):
    ax.set_visible(True)
    setup_axes(xhi=1.6)
    labels = ["undefended", "+ security\nprompt"]
    fix = seg(t, 2.8, 5.0)
    colors = [RED, hexlerp(BLUE, GREEN, fix)]
    _bars(labels, [0.0, 1.0 * fix], colors, A=A, label_dy=-0.08)
    aa = seg(t, 2.8, 4.0)
    if aa > 0:
        ax.annotate("", xy=(0.98, 0.96 * fix), xytext=(0.12, 0.1),
                    arrowprops=dict(arrowstyle="-|>", color=GREEN, lw=2.4,
                                    alpha=aa * A, connectionstyle="arc3,rad=-0.25"))
    if t < 2.6:
        title_caption("Can a cheap defense fix it?",
                      "Undefended, the attacker wins every time.", A)
    else:
        title_caption("Can a cheap defense fix it?",
                      "Four sentences of system prompt restore it to 100%.", A, capcolor=INK)


def scene_adapt(t, A):
    ax.set_visible(True)
    setup_axes(xhi=1.6)
    labels = ["security\nprompt", "spotlighting\n(markers)"]
    naive = [1.0, 1.0]
    after = [1.0, 0.67]            # adaptive attacker, banking suite (verified)
    grow = seg(t, 0.3, 1.9)
    attack = seg(t, 3.0, 5.6)
    heights = [lerp(naive[i] * grow, after[i], attack) if t >= 3.0 else naive[i] * grow
               for i in range(2)]
    colors = [hexlerp(BLUE, GREEN if after[i] >= 0.8 else RED, attack) for i in range(2)]
    ghosts = [None, (1.0 if attack > 0.05 else None)]
    _bars(labels, heights, colors, ghosts, A=A, label_dy=-0.08)
    la = seg(t, 3.0, 4.2)
    if la > 0:
        T(0.30, 0.735, "HELD", 13, GREEN, la * A, weight="bold")
        T(0.72, 0.735, "FELL", 13, RED, la * A, weight="bold")
    if t < 2.8:
        title_caption("Does the defense survive an attacker?",
                      "Both stop every canned attack. Looks solved.", A)
    else:
        title_caption("Does the defense survive an attacker?",
                      "An adaptive attacker walks past the marker defense.", A, capcolor=INK)


def scene_close(t, A):
    ax.set_visible(False)
    T(0.5, 0.72, "Capability won't tell you.", 26, INK, A, weight="bold")
    T(0.5, 0.655, "The leaderboard won't tell you.", 26, INK, A * seg(t, 0.4, 1.2), weight="bold")
    T(0.5, 0.55, "So scan your own agent.", 30, RED, A * seg(t, 1.4, 2.2), weight="bold")
    T(0.5, 0.36, "Open-source injection benchmark + CI gate.",
      16, INK2, A * seg(t, 2.0, 2.8))
    T(0.5, 0.30, "A model upgrade that breaks security fails the build.",
      15, INK2, A * seg(t, 2.2, 3.0))
    T(0.5, 0.15, "github.com/immu4989/dspy-security-bench", 16, INK,
      A * seg(t, 2.6, 3.4), weight="bold")


DISPATCH = {"teaser": scene_teaser, "cap": scene_cap, "fix": scene_fix,
            "adapt": scene_adapt, "close": scene_close}


def draw(frame):
    t = frame / FPS
    fig.texts.clear()
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
    out = os.path.join(out_dir, "dsb-story.mp4")
    anim = FuncAnimation(fig, draw, frames=FRAMES, interval=1000 / FPS, blit=False)
    writer = FFMpegWriter(fps=FPS, bitrate=4800, extra_args=["-pix_fmt", "yuv420p"])
    anim.save(out, writer=writer, dpi=120, savefig_kwargs={"facecolor": BG})
    print(f"wrote {out}  ({os.path.getsize(out) / 1e6:.1f} MB, {DURATION:.0f}s, {FRAMES} frames)")


if __name__ == "__main__":
    main()
