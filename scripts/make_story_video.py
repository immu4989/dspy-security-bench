#!/usr/bin/env python3
"""One 1080x1080 story video for dspy-security-bench, as MP4.

Spine (the house grammar): every result looked fine, then the honest check
made it collapse.

  Hook   — "Upgraded the model. Benchmarks said better. Security: broken."
  Act 1  — capability: 4 models' injection-security; the more capable Mistral
           collapses within its own family (Small 100% -> Large 0%).
  Act 2  — the fix: undefended Mistral Large 0% -> a 4-sentence security
           prompt restores it to 100%.
  Act 3  — the honest check: point an adaptive attacker at the defenses; the
           clever marker defense (spotlighting) breaks, the simple one holds.
  Close  — "You can't tell by looking. Scan yours." + repo link.

Uses matplotlib + pip-installed static ffmpeg (imageio-ffmpeg); no system ffmpeg.
Run with the interpreter that has imageio_ffmpeg (system python3 on this box):

    python3 scripts/make_story_video.py
    ->  ~/Documents/dspy-security-bench-social/dsb-story.mp4
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

BG = "#fbfbf9"
INK = "#14171c"
INK2 = "#52514e"
MUTED = "#8a8a84"
GRID = "#e6e5df"
BLUE = "#2a78d6"
GREEN = "#1baf7a"
RED = "#e34948"
AMBER = "#d9a441"

FPS = 24
FADE = 0.3

SCENES = [
    ("hook", 5.0),
    ("cap", 9.0),
    ("fix", 8.0),
    ("adapt", 9.0),
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


def setup_axes(xhi=3.6, ymax=1.16):
    ax.clear()
    ax.set_facecolor("none")
    ax.set_xlim(-0.6, xhi)
    ax.set_ylim(0, ymax)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])
    for gy in (0.25, 0.5, 0.75, 1.0):
        ax.axhline(gy, color=GRID, lw=1, zorder=0)
    ax.axhline(0, color="#cfcec6", lw=1.5)


def _bars(labels, heights, colors, ghosts=None, A=1.0, label_dy=-0.055, fs_lab=11):
    for i in range(len(labels)):
        if ghosts and ghosts[i] is not None:
            ax.add_patch(plt.Rectangle((i - 0.31, 0), 0.62, ghosts[i], fill=False,
                                       ec=MUTED, ls=(0, (3, 3)), lw=1.1, alpha=0.55 * A))
        ax.bar(i, heights[i], width=0.62, color=colors[i], alpha=A, zorder=3)
        if heights[i] > 0.02:
            ax.text(i, heights[i] + 0.02, f"{heights[i]:.0%}", ha="center", va="bottom",
                    fontsize=12, color=INK2, fontweight="bold", alpha=A)
        else:
            ax.text(i, 0.02, "0%", ha="center", va="bottom",
                    fontsize=12, color=RED, fontweight="bold", alpha=A)
        ax.text(i, label_dy, labels[i], ha="center", va="top", fontsize=fs_lab,
                color=INK, alpha=A)


# ------------------------------------------------------------------ scenes
def scene_hook(t, A):
    ax.set_visible(False)
    beats = [(0.2, "Upgraded to a more capable model."),
             (1.1, "Every benchmark said: better."),
             (2.0, "Its security: silently broken.")]
    for i, (t0, txt) in enumerate(beats):
        col = RED if i == 2 else INK
        a = A * ease((t - t0) / 0.35) * (1.0 if t < 3.3 else clamp((3.8 - t) / 0.4))
        T(0.5, 0.64 - i * 0.10, txt, 27 if i < 2 else 29, col, a, weight="bold")
    if t >= 3.5:
        a = A * ease((t - 3.5) / 0.4)
        T(0.5, 0.40, "Prompt injection.", 20, INK2, a)
        T(0.5, 0.35, "You can't tell which models are exposed by looking.", 16, INK2, a)


def scene_cap(t, A):
    ax.set_visible(True)
    setup_axes(xhi=3.6)
    labels = ["gpt-4o-mini", "Mistral\nSmall", "Mistral\nLarge", "DeepSeek V3"]
    real = [0.80, 1.00, 0.00, 0.80]   # unoptimized injection-security (harder attack)
    grow = seg(t, 0.4, 2.4)
    reveal = seg(t, 3.4, 5.2)
    heights = [real[i] * grow for i in range(4)]
    colors = []
    for i in range(4):
        final = RED if real[i] < 0.3 else GREEN
        colors.append(hexlerp(BLUE, final, reveal) if t >= 3.4 else BLUE)
    # ghost on Mistral Large showing the within-family drop from Small's 100%
    ghosts = [None, None, (1.0 if reveal > 0.05 else None), None]
    _bars(labels, heights, colors, ghosts, A=A, label_dy=-0.055)
    # "same family" bracket over Small + Large
    ba = seg(t, 3.4, 4.4)
    if ba > 0:
        ax.plot([0.62, 2.38], [1.10, 1.10], color=MUTED, lw=1.2, alpha=ba * A)
        ax.text(1.5, 1.115, "same family", ha="center", va="bottom", fontsize=11,
                style="italic", color=MUTED, alpha=ba * A)
    if t < 3.2:
        title_caption("Which model resists prompt injection?",
                      "Injection-security across four models. So far so good.", A)
    else:
        title_caption("Which model resists prompt injection?",
                      "Scale up within a family and it collapses to zero.", A, capcolor=INK)


def scene_fix(t, A):
    ax.set_visible(True)
    setup_axes(xhi=1.6)
    labels = ["undefended", "+ security\nprompt"]
    grow = seg(t, 0.4, 2.0)
    fix = seg(t, 3.2, 5.4)
    heights = [0.0, 1.0 * fix]      # undefended stays 0; the fix grows back to 100%
    # keep a small blue "attempt" on undefended during grow so it reads as measured
    h0 = 0.0
    colors = [RED, hexlerp(BLUE, GREEN, fix)]
    _bars(labels, [h0, heights[1]], colors, A=A, label_dy=-0.08)
    # arrow from the 0% bar up to the restored bar
    aa = seg(t, 3.2, 4.4)
    if aa > 0:
        ax.annotate("", xy=(1, 0.9 * fix), xytext=(0.1, 0.12),
                    arrowprops=dict(arrowstyle="-|>", color=GREEN, lw=2.2,
                                    alpha=aa * A, connectionstyle="arc3,rad=-0.25"))
    if t < 3.0:
        title_caption("Can a cheap defense fix it?",
                      "Mistral Large, undefended: attacker wins every time.", A)
    else:
        title_caption("Can a cheap defense fix it?",
                      "Four sentences of system prompt restore it to 100%.", A, capcolor=INK)


def scene_adapt(t, A):
    ax.set_visible(True)
    setup_axes(xhi=1.6)
    labels = ["security\nprompt", "spotlighting\n(markers)"]
    naive = [1.0, 1.0]              # both look perfect vs canned attacks
    after = [1.0, 0.67]            # under an adaptive attacker on a 2nd suite (banking, verified)
    grow = seg(t, 0.4, 2.2)
    attack = seg(t, 3.4, 6.0)
    heights = [lerp(naive[i] * grow, after[i], attack) if t >= 3.4 else naive[i] * grow
               for i in range(2)]
    colors = [hexlerp(BLUE, GREEN if after[i] >= 0.8 else RED, attack) for i in range(2)]
    ghosts = [None, (1.0 if attack > 0.05 else None)]
    _bars(labels, heights, colors, ghosts, A=A, label_dy=-0.08)
    la = seg(t, 3.4, 4.6)
    if la > 0:
        T(0.30, 0.735, "HELD", 13, GREEN, la * A, weight="bold")
        T(0.72, 0.735, "FELL", 13, RED, la * A, weight="bold")
    if t < 3.2:
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


DISPATCH = {"hook": scene_hook, "cap": scene_cap, "fix": scene_fix,
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
    writer = FFMpegWriter(fps=FPS, bitrate=4500, extra_args=["-pix_fmt", "yuv420p"])
    anim.save(out, writer=writer, dpi=120, savefig_kwargs={"facecolor": BG})
    print(f"wrote {out}  ({os.path.getsize(out) / 1e6:.1f} MB, {DURATION:.0f}s, {FRAMES} frames)")


if __name__ == "__main__":
    main()
