# Related work: agentic prompt injection, as of July 2026

A map of what has already been measured, by whom, and with what caveats. Written
because this area is easy to misread: several widely-cited numbers measure
different things, and a few well-known "leaderboards" do not rank what people
think they rank.

Everything below was checked against the primary paper, PDF, or vendor document.
Anything not verified that way is marked **[unverified]**.

---

## 1. The capability–robustness relationship is settled

If you are looking for the finding "prompt-injection robustness does not track
model capability", it is published, repeatedly, and in paper abstracts.

| Work | Scale | Claim |
|---|---|---|
| **Gray Swan ART** — [arXiv:2507.20526](https://arxiv.org/abs/2507.20526) (Jul 2025) | 22 agents, 19 models, 44 scenarios, 1.8M attacks | Abstract: *"we find limited correlation between agent robustness and model size, capability, or inference-time compute"* |
| **IPI competition** — [arXiv:2603.15714](https://arxiv.org/abs/2603.15714) (Mar 2026), Gray Swan + OpenAI + Meta + Anthropic + UK AISI + US CAISI | 13 frontier models, 272K attempts, 41 agentic scenarios | Abstract: *"Capability and robustness showed weak correlation, with Gemini 2.5 Pro exhibiting both high capability and high vulnerability"* |
| **b³ / Backbone Breaker** — [arXiv:2510.22620](https://arxiv.org/abs/2510.22620), Lakera + UK AISI | 34 LLMs, 194,331 attacks | Abstract: *"enhanced reasoning capabilities improve security, while model size does not correlate with security"* |
| **Li et al.** — [arXiv:2308.10819](https://arxiv.org/abs/2308.10819), EMNLP 2024 | ~10 models | Size and instruction-following capability do not track robustness |
| **Sun & Miceli-Barone** — [arXiv:2403.09832](https://arxiv.org/abs/2403.09832) | Multiple families | Explicit inverse scaling for prompt injection in MT |

A third-party writeup reports a correlation of r = −0.31, p = 0.3 between GPQA
Diamond and ASR for the 13-model set. **[unverified]** — the qualitative claim is
in the abstract; whether that exact coefficient appears in the paper body was not
confirmed.

Note these three results do **not** fully agree. ART and the IPI competition say
capability does not predict robustness; b³ says *reasoning* specifically does
improve it; ASB ([arXiv:2410.02644](https://arxiv.org/abs/2410.02644)) reports a
non-monotonic shape where ASR rises with capability and then falls as refusal
behaviour appears. Reconciling reasoning, scale and refusal as separate axes is,
as far as this survey found, still open.

### The "instruction-following tax"

Also published, by two major labs:

- **Google DeepMind**, [arXiv:2505.14534](https://arxiv.org/abs/2505.14534):
  *"models that have better instruction following capabilities are in some cases
  easier to attack, and so, improving general capabilities of a model does not
  automatically result in a more robust model"*, plus the corollary that
  *"a lack of certain capabilities ... shouldn't be mistaken for a secure model."*
- **Meta SecAlign**, [arXiv:2507.02735](https://arxiv.org/abs/2507.02735) §5.3:
  *"Without defense, stronger LLMs tend to suffer from higher ASRs as hypothesized."*
- **WASP** ([arXiv:2504.18575](https://arxiv.org/abs/2504.18575)) names the
  low-capability case **"security by incompetence"** — the reason any security
  number reported without a utility number is uninterpretable.

---

## 2. Static evaluation overstates robustness

The most important methodological result in this area, and the reason a fixed-
template benchmark (including this one) should be read narrowly.

Google DeepMind, [arXiv:2505.14534](https://arxiv.org/abs/2505.14534), on Gemini 2.5:

> *"Had we not conducted further adaptive attacks and evaluations, we would have
> incorrectly concluded that Gemini 2.5 exhibits a higher degree of robustness
> than it does."*

| Evaluation | Gemini 2.5 ASR |
|---|---|
| Static transfer (triggers optimised against Gemini 2.0) | 18% |
| Adaptive (re-optimised against Gemini 2.5) | 53.6% – 94.6% |

The same paper shows spotlighting collapsing from 0.180 to **0.824** ASR once the
attack is adapted to it, and puts the cost of building a working trigger against
Gemini 2.0 Flash at **under $10**.

Related: [arXiv:2510.05244](https://arxiv.org/abs/2510.05244) argues AgentDojo,
ASB, InjecAgent and τ-bench are all saturated by trivial model-agnostic
firewalls, attributing this to *"flawed success metrics, implementation bugs,
and most importantly, weak attacks."* Any benchmark built on these suites —
this one included — has to be read with that in mind.

---

## 2b. What a reported attack-success number is contingent on

A single ASR figure is under-determined along at least five axes. Each is
published, several of them long before the LLM era. Anyone measuring defenses —
including this repository — is choosing a point on all five whether or not they
say so.

| Axis | Established by |
|---|---|
| **Attack budget** (iterations, restarts, rounds) | [Carlini et al. 2019](https://arxiv.org/abs/1902.06705); [Tramèr et al. 2020](https://arxiv.org/abs/2002.08347); [BoN, 2412.03556](https://arxiv.org/abs/2412.03556) |
| **Attack method** (static template vs adaptive search) | [The Attacker Moves Second, 2510.09023](https://arxiv.org/abs/2510.09023); [2505.14534](https://arxiv.org/abs/2505.14534) |
| **Attacker model identity** | [PAIR, 2310.08419](https://arxiv.org/abs/2310.08419); [2505.20162](https://arxiv.org/abs/2505.20162); **for prompt injection specifically:** [2606.10525](https://arxiv.org/abs/2606.10525) |
| **Random seed / run-to-run variance** | [2605.14418](https://arxiv.org/abs/2605.14418); [2512.12066](https://arxiv.org/abs/2512.12066) |
| **Judge / evaluator model** | [TAP, 2312.02119](https://arxiv.org/abs/2312.02119) Table 4 |

### Budget

Carlini et al.'s 2019 evaluation checklist already says it plainly:

> *"Verify that doubling the number of iterations does not increase attack
> success rate."* … *"There are few reasonable threat models under which an
> attacker can compute 100 iterations of gradient descent, but not 1000."*

Tramèr et al. 2020 shows the same collapse for defenses, noting that published
evaluations used *"only 10 iterations … unlikely to allow the attacks to
converge."* [Andriushchenko et al. 2024](https://arxiv.org/abs/2404.02151)
Table 15 has the cleanest exhibit: Claude 2.0 moves **2% → 12% → 48%** at 1, 10
and 100 restarts. Nothing about the defense changed.

### Attacker model, in prompt injection

[arXiv:2606.10525](https://arxiv.org/abs/2606.10525) (Debenedetti, Tramèr — the
AgentDojo authors) holds target, defense, task and budget fixed and swaps only
the attacker LM:

> *"TAP's effectiveness depends on the attacker model, as both general
> capability and safety tuning affect attack success — stronger models produce
> more effective injections, while safety-tuned attackers can refuse to generate
> adversarial prompts."*

GPT-5-mini → GPT-5 as attacker moves ASR 36.6% → 44.6% (single-task) and
10.7% → 45.2% (universal).

Counter-intuitively, a *more capable* attacker is not always better: PAIR's
attacker ablation finds GPT-3.5 the **worst** of three, behind Mixtral and
Vicuna, because *"Mixtral and Vicuna lack the safety alignment of GPT-3.5, which
is helpful for red-teaming."* Attacker-side refusal is a confound in its own
right.

### Variance

> *"ASR is not a stable quantity … published ASR numbers are therefore
> systematically inflated and incomparable across papers."*
> — [2605.14418](https://arxiv.org/abs/2605.14418)

[2512.12066](https://arxiv.org/abs/2512.12066) finds 18–28% of prompts flip
decision across seeds and temperatures, and recommends at least 3 samples per
prompt. A single run is not a measurement.

Worth noting what the major benchmarks do about this: JailbreakBench answers
"No" to the error-bar checklist item and puts attack randomness out of scope;
HarmBench assumes deterministic greedy decoding; AgentDojo *does* report 95%
confidence intervals, but they are binomial over its fixed test cases rather
than over repeated runs. The distinction matters and is rarely drawn.

## 3. Attack budget dominates the headline number

The same model produces wildly different ASRs depending only on how many attempts
the attacker gets. Claude Opus 4.5, from published sources:

| Setting | ASR |
|---|---|
| IPI competition, live | 0.5% |
| Transfer replay of curated attacks | 2.5% |
| Strong attacker, k=1 | 4.7% **[unverified]** |
| k=10 | 33.6% **[unverified]** |
| k=100 | 63% **[unverified]** |

A ~126× spread. **A model-level robustness number without a stated attack budget
and surface is under-determined.** The k-values above come from secondary
reporting of a vendor system card and were not confirmed against the card itself.

### Surface matters as much as k

[arXiv:2606.05233](https://arxiv.org/abs/2606.05233) (Patronus / UC Berkeley)
found the same weights behaving completely differently by surface: Claude Sonnet
4.6 scored **0/140 (0%)** on multi-step browser injection but **40/40 (100%)** on
coding-skill injection. **LivePI** ([arXiv:2605.17986](https://arxiv.org/abs/2605.17986),
Penn) reports **100% ASR on a group-chat surface for every frontier model tested**,
traced to group messages entering context with role `user` while tool output uses
`toolResult`.

---

## 4. What the existing "leaderboards" actually rank

A recurring source of confusion. None of these is a live cross-model
prompt-injection ranking:

| Resource | What it actually ranks |
|---|---|
| [AgentDojo results page](https://agentdojo.spylab.ai/results/) | Per-model results, but the page states outright *"this is **not** a leaderboard"*; coverage is uneven and data ends **2025-02-24** |
| Gray Swan Arena | **Humans** (red-teamers), not models |
| Lakera PINT | **Detectors / guardrails**, not models |
| Cisco AI Defense, F5 CASI/ARS, Enkrypt | Models, but with **no prompt-injection subscore** |
| Vendor system cards | Self-reported, and typically the vendor's own models *without* safeguards against competitors' *production endpoints* |

Do not cite ART ([2507.20526](https://arxiv.org/abs/2507.20526)) for any model
newer than Gemini 2.5 Pro Preview, and do not cite the AgentDojo results table
for anything after February 2025.

### Reading vendor numbers

- **Attempt-level and scenario-level ASR are routinely conflated.** "31.5%" and
  "81/129" (62.8%) can be the same row of the same table.
- **Cross-generation comparisons inside one vendor's cards are often invalid** —
  evaluations get re-hardened once a model saturates them.
- **Benchmarks are being deprecated mid-stream** as they saturate.

---

## 5. Benchmarks in this space

| Benchmark | Reference |
|---|---|
| AgentDojo | [arXiv:2406.13352](https://arxiv.org/abs/2406.13352), NeurIPS 2024 D&B |
| InjecAgent | [arXiv:2403.02691](https://arxiv.org/abs/2403.02691) |
| Agent Security Bench (ASB) | [arXiv:2410.02644](https://arxiv.org/abs/2410.02644) |
| WASP | [arXiv:2504.18575](https://arxiv.org/abs/2504.18575) |
| b³ / Backbone Breaker | [arXiv:2510.22620](https://arxiv.org/abs/2510.22620) |
| Automated attacks on AgentDojo | [arXiv:2606.10525](https://arxiv.org/abs/2606.10525) — by the AgentDojo authors |
| LivePI | [arXiv:2605.17986](https://arxiv.org/abs/2605.17986) |
| CUA-Handcrafted | [arXiv:2606.05233](https://arxiv.org/abs/2606.05233) |
| Firewalls / benchmark critique | [arXiv:2510.05244](https://arxiv.org/abs/2510.05244) |

---

## 6. Where this repository sits

This benchmark measures **static, fixed-template** injection attacks
(AgentDojo's `important_instructions` and `direct`) at **k=1** against a
**ReAct-style tool-use agent** on **two suites**. Given sections 2 and 3, that is
a narrow slice, and its numbers should be read as a lower bound on
attackability rather than as a robustness guarantee.

Its results are **consistent with** the published work above rather than
independent of it — for example this board measures Claude Sonnet 4.5 at 99.3%
robustness under `important_instructions`, against the 1.0% ASR independently
measured for the same model in the IPI competition.

What it offers that the works above do not is **reproducibility at low cost**: a
frozen protocol, committed per-row result JSONs, and a runner anyone can point at
a new model for a few dollars. A 464-participant competition cannot be re-run by
a third party; this can.
