# Paper outline — IEEE SaTML 2027

**Status:** working draft. Not committed to git history as repo content; this is a
planning document.

**Target:** IEEE SaTML 2027 — deadline **2026-09-29 AoE**, notification 2026-12-16,
conference May 2027, Reykjavik. Research-paper track (also accepts SoK / position).
**arXiv:** post on submission day.

Every section below is tagged with data status:
- **HAVE** — data exists at publication scale, already collected
- **PILOT** — data exists but single-model and/or n<10; NOT publishable as-is
- **NEED** — must be generated before submission

---

## Working title

*Injection-Robustness Is Not a Capability: Measuring Prompt-Injection Resistance
Across 14 Language Models*

Alternatives:
- *The 76-Point Gap: Prompt-Injection Robustness Is Orthogonal to Model Capability*
- *Capability Does Not Buy Robustness: A Frozen-Protocol Leaderboard for Agentic
  Prompt Injection*

## Thesis (one sentence)

Prompt-injection robustness in tool-using agents varies from 23% to 99% across
current models, does not track capability or scale, and is therefore a distinct
engineering property that capability benchmarks cannot predict.

## Claimed contributions

1. A frozen, reproducible measurement protocol for agentic injection-robustness,
   with an explicit durability rule (a result is *confirmed* only when its CI lies
   inside one bucket and the bucket is stable across repeats).
2. The first cross-vendor leaderboard of base-model injection-robustness at this
   scale: 14 models, 10 families, 450 scored attack attempts per model.
3. Evidence that robustness is orthogonal to capability, including three
   within-family comparisons that move in *both* directions.
4. Public artifact: leaderboard, protocol, runner, per-row result JSONs.

---

## Section plan

### 1. Introduction
Agentic deployments put untrusted text into the model's context by design (tool
output, retrieved documents, emails). Capability leaderboards say nothing about
whether a model will obey instructions found there. **NEED:** framing + citations.

### 2. Related work
AgentDojo, InjecAgent, WASP, BIPIA; prompt-injection defenses (spotlighting,
sandwich, instruction hierarchy); the alignment-vs-capability literature.
**NEED:** proper survey; ~30-40 refs.

### 3. Protocol
Frozen measurement contract; bucket claims; confirm/provisional durability gate;
disclosed subset; identical attack templates across models.
**HAVE** — `leaderboard/protocol.yaml`, verbatim.

> Reviewer-facing strength: the confirm/provisional rule is unusual and defensible.
> Lead with it — most benchmark papers report point estimates with no stability
> criterion at all.

### 4. Results: the leaderboard  ← **the core contribution**
**HAVE** — 14 models, 10 families, 13 confirmed + 1 provisional.

- **Table 1** — full board: model, family, R, 95% CI, bucket, per-suite. *(HAVE)*
- **Figure 1** — ranked bars w/ CI (`assets/leaderboard_hero.png`). *(HAVE)*
- **Table 2** — within-family comparisons *(HAVE)*:
  | Vendor | Change | R |
  |---|---|---|
  | OpenAI: gpt-4o-mini → GPT-5.4 mini | newer generation | 86% → 99% |
  | Meta: Llama 3.3 70B → Llama 4 Maverick | newer generation | 53% → 86% |
  | NVIDIA: Nemotron Nano 30B → Super 120B | scaled 4× | 95% → 78% |
- **Figure 2** — NVIDIA within-family drop (`assets/within_family_nvidia.png`). *(HAVE)*
- **Observation** — Grok 4.3 shows the widest cross-suite spread (58% workspace vs
  87% banking), evidence that single-environment benchmarks mis-rank. *(HAVE)*

### 5. Attack generality  ← **BIGGEST REJECTION RISK**
Currently only `important_instructions` at board scale.
**NEED:** run `direct` across all 14 models (code exists, `--headline-only` off).
Ideally a third AgentDojo attack. Without this, a reviewer says the finding may be
an artifact of one attack template.

### 6. Mechanism: the instruction-following tax
Trace-level evidence that a vulnerable model explicitly reasons about obeying
injected instructions and then calls the attacker's tool, confirmed by AgentDojo's
functional check.
**PILOT** — qualitative, Mistral Large only (`scripts/verify_injection_trace.py`).
**NEED:** systematise — trace-classify N failures across ≥3 vulnerable models.

### 7. Do cheap defenses close the gap?
**PILOT ONLY — NOT PUBLISHABLE AS-IS.**
Existing data: Mistral Large, n=3 (banking) / n=5 (workspace), 4 defenses.
**NEED:** re-run defenses under the frozen protocol across the vulnerable cohort
(Mistral Large, Mistral Medium 3.1, DeepSeek V3.2, Qwen3 235B).

### 8. Do the defenses survive an adaptive attacker?
**PILOT ONLY.** Existing: rule-based + LM-driven adaptive attacks, Mistral Large.
Prior finding — security-prompt held, spotlighting fell to 67% — is directionally
interesting but underpowered.
**NEED:** same cohort as §7, adequate n.

### 9. Limitations (write this honestly, it earns credibility)
- Disclosed task subset, not full suites.
- Single agent scaffold (`dspy.ReActV2`).
- Attack templates fixed to one pipeline name for fairness across models.
- `greedy_honored` unverified per provider.
- Models measured at one point in time; vendors ship changes.

### 10. Conclusion + artifact release

---

## Scope decision

Two viable papers:

**(A) Measurement paper — leaderboard + attack generality.** §1-6, 9, 10.
Needs only §5 (the `direct` attack sweep) plus writing. **Achievable by Sept 29.**

**(B) Full arc — adds defenses + adaptive attacks.** Also needs §7-8 re-run at
scale. Stronger paper, materially more compute and time.

**Recommendation: (A).** It is a complete, defensible contribution on its own, and
§7-8 become the natural follow-up paper. Attempting (B) in two months risks an
underpowered defenses section that drags down an otherwise strong submission —
reviewers punish a weak section more than a missing one.

## Compute still required for (A)

| Item | Est. |
|---|---|
| `direct` attack × 14 models | ~$12-15 |
| (optional) full-coverage re-run of top/bottom rows | ~$20 |
| **Total** | **~$15-35** |

Current OpenRouter balance ≈ $22. A ~$25 top-up covers (A) comfortably.

## Timeline

| Window | Work |
|---|---|
| Aug wk 1-2 | `direct` sweep; regenerate board with both attacks |
| Aug wk 3 | Related work + citations |
| Aug wk 4 | Draft §1-4 |
| Sep wk 1-2 | Draft §5-6, 9-10; figures to camera-ready quality |
| Sep wk 3 | Internal review pass; tighten claims |
| Sep 29 | Submit SaTML + post arXiv |
