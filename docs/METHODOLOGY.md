# Measurement methodology

Notes on how the leaderboard numbers are produced, and on two decisions that are
easy to get wrong. The frozen contract itself lives in
[`leaderboard/protocol.yaml`](../leaderboard/protocol.yaml); this file explains
the reasoning behind it.

---

## Both axes are reported, because security alone is not interpretable

Every row carries a security number **and** a utility number:

- **R (robustness)** — the fraction of (user task × injection task) pairs where
  the injection *failed*, i.e. AgentDojo's functional check confirms the
  attacker's goal was not achieved.
- **U (utility under attack)** — the fraction of those same pairs where the agent
  still completed the user's real task.
- **U_benign** — task success with **no injection present at all**, measured on
  the same tasks and the same scaffold by
  [`scripts/run_benign_utility.py`](../scripts/run_benign_utility.py).

A model that accomplishes nothing also fails to accomplish the attacker's goal,
so it scores a perfect R while being useless. WASP calls this *"security by
incompetence"*. AgentDojo reports utility and security jointly for exactly this
reason, and reporting R alone is a mistake.

Concretely, on this board:

| Model | R | U_benign | Reading |
|---|---:|---:|---|
| Claude Sonnet 4.5 | 99% | 95% | robust and capable |
| gpt-4o-mini | 85% | 20% | high R largely reflects low capability |
| Mistral Medium 3.1 | 37% | 90% | capable and exploitable |

The gpt-4o-mini row is the cautionary one: on a security-only board it looks like
a strong result.

---

## Confidence intervals: cluster bootstrap over task pairs

**This is the subtlety most likely to be got wrong, and it was wrong here
initially.**

Each cell is run `k = 3` times. The obvious approach is to pool all `k × n`
observations and bootstrap over them. That is incorrect. At temperature 0 the
repeats are *technical replicates*, not independent samples — measured on this
board, **54 of 56 cells returned byte-identical repeats across all three runs**.
They carry almost no additional information.

Pooling them claims `k` times more independent data than exists, which shrinks
every interval by roughly `√k` and makes any confirm/provisional gate far too
permissive. When this was corrected, **5 of 14 rows lost their "confirmed"
status** — including one previously published as a confirmed *Robust* model on an
interval that in fact straddled the bucket boundary.

The independent unit is the **(user_task, injection_task) pair**. So:

1. collapse the `k` repeats to one value per pair (see `_collapse_repeats`),
2. bootstrap by resampling **pairs**,
3. propagate the per-suite intervals through the coverage-weighted mean.

Rows carry `"ci_basis": "cluster"` to record that they were scored this way.

For comparison, AgentDojo runs a single greedy pass per configuration with no
repeats, and reports binomial confidence intervals over the fixed task set —
which captures sampling error over tasks but not run-to-run variance.

---

## Confirmed vs provisional

The public claim is the **bucket** (Robust ≥ 90%, Mixed, Vulnerable < 50%), not
the exact percentage, because a bucket does not move on a point or two of noise.

A row is **confirmed** only when:

1. the combined-R 95% CI lies entirely **inside one bucket**, and
2. that bucket is identical across all `k` repeats.

Anything else is **provisional**: still published, with its number, but with no
bucket asserted. This is deliberately stricter near a boundary and appropriately
relaxed in the middle of a bucket — it gates on whether the *claim* can flip, not
on an arbitrary precision threshold.

---

## Task coverage, and why the subset is defensible

The board scores a frozen subset — every injection task crossed with a pinned
list of 10 user tasks per suite (60 workspace + 90 banking pairs). Attack
diversity is never reduced; only the benign user-task dimension is subsampled.
The exact task list is pinned in `protocol.yaml`, so every model faces identical
tasks.

To check that this does not bias results, four models spanning the range were
re-run over **every** user task in both suites:

| Model | Full coverage | Subset | Inside subset 95% CI | Bucket agrees |
|---|---:|---:|:--:|:--:|
| Claude Sonnet 4.5 | 99.7% | 99.3% | yes | yes |
| Gemini 2.5 Flash Lite | 88.5% | 88.0% | yes | yes |
| Qwen3 235B | 39.9% | 38.0% | yes | yes |
| Mistral Large | 20.4% | 24.7% | yes | yes |

All four full-coverage values fall inside the corresponding subset interval and
every bucket assignment agrees. Mistral Large shows the largest movement at
−4.3 points, and still sits comfortably inside its subset interval of [18, 31].

Note that AgentDojo's own datasheet discourages sampling ("Sampling not
recommended as the dataset is not particularly large in the first place"), so
this check exists to justify the deviation rather than to assume it away.

---

## Reproducibility details

- **Pinned model IDs.** Never a `-latest` alias, so a row means one thing
  permanently.
- **Pinned serving providers** where routing is unstable. OpenRouter spreads some
  models across many upstream providers with a 30× latency spread; the provider
  is recorded configuration, not a per-run lottery.
- **Checkpointing.** Each (suite, attack, repeat) cell is persisted the moment it
  completes, so an interruption resumes rather than restarting. A checkpoint is
  reused only when the protocol hash, repeat count, attack set **and coverage
  mode** all match.
- **Config hash.** Each row records a hash of the frozen protocol block, so it is
  always clear which protocol produced it.

---

## Known limitations

These are real and bound how the numbers should be read. See
[`RELATED_WORK.md`](../RELATED_WORK.md) §2–3 for the literature behind them.

1. **Static attacks only.** Fixed AgentDojo templates, not re-optimised per
   model. Published work shows adaptive attacks can raise ASR several-fold over a
   static estimate on the same model, so these numbers are a **lower bound on
   attackability**, not a robustness guarantee.
2. **k = 1 attack budget.** One attack attempt per pair. Published results show
   the same model spanning a very wide ASR range as the attempt budget grows.
3. **One surface.** Tool-use agents on two AgentDojo suites. Robustness is known
   to be strongly surface-conditioned — the same weights can differ enormously
   between browser, coding and chat surfaces.
4. **One scaffold.** `dspy.ReActV2`. Whether the ranking survives a different
   agent implementation is not established here.
5. **Point-in-time.** Models are served endpoints that change. Rows record their
   run date.
