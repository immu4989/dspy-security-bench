# dspy-security-bench

Measure how DSPy prompt optimization affects the prompt-injection robustness of
agentic LLM programs, using [AgentDojo's](https://github.com/ethz-spylab/agentdojo)
attack suite as ground truth.

**Status:** v0.1 / alpha. The core pipeline runs end-to-end; v0.1 evaluates the
AgentDojo `workspace` suite. Banking/travel/slack suites work via a generic
fallback; suite-tuned extractors are pending. Empirical results in this README
will be published after the first full v0.1 run.

## The question this benchmark answers

When you optimize a DSPy program with `BootstrapFewShot`, `MIPROv2`, or `GEPA`,
does the resulting program become *more* or *less* robust to prompt-injection
attacks?

Two adjacent communities have not talked to each other:

- **Prompt-optimization research** (MIPROv2, GEPA, ParetoPrompt, MOPrompt,
  syftr) measures accuracy gains after optimization. None of these papers
  evaluate the optimized prompts under adversarial input.
- **Prompt-injection / jailbreak research** (InjecAgent, AgentDojo, WASP,
  AgentNoiseBench) measures attack success against *static* prompts. They
  don't study what optimization does to robustness.

`dspy-security-bench` wires these together: it runs DSPy optimizers over a
synthesized in-distribution trainset, then evaluates the optimized programs
against AgentDojo's attack suite, producing a per-`(optimizer, attack)` matrix
of utility vs security trade-offs.

## How it works

```
                  AgentDojo seed env data
                            │
                            ▼
                  ┌──────────────────────┐
                  │  env-data extractor  │
                  └──────────┬───────────┘
                             │
       LLM (gpt-4o, claude)  ▼
            ┌─────────────────────────────┐
            │  synthesis generator        │
            │  (LM-generated query-only   │
            │   tasks grounded in env)    │
            └──────────────┬──────────────┘
                           │  raw tasks
                           ▼
            ┌─────────────────────────────┐
            │  validator                  │
            │  (syntactic + dedupe +      │
            │   optional solvability)     │
            └──────────────┬──────────────┘
                           │  ~100 validated tasks per suite
                           ▼
            ┌─────────────────────────────┐
            │  optimizer harness          │
            │  (Unoptimized, Bootstrap,   │
            │   MIPROv2; GEPA in v0.2)    │
            └──────────────┬──────────────┘
                           │  {name: agent_factory}
                           ▼
            ┌─────────────────────────────┐
            │  DSPyReActV2Element         │
            │  (wraps a dspy.ReActV2 as   │
            │   an AgentDojo pipeline     │
            │   element; tools bind to    │
            │   AgentDojo runtime + env)  │
            └──────────────┬──────────────┘
                           │  AgentPipeline
                           ▼
            ┌─────────────────────────────┐
            │  runner                     │
            │  (drives benchmark_suite_   │
            │   with_injections across    │
            │   factories × attacks)      │
            └──────────────┬──────────────┘
                           │
                           ▼
                    pandas.DataFrame
                  (one row per
                  optimizer × attack ×
                  user_task × injection_task)
```

## Install

```bash
git clone https://github.com/immu4989/dspy-security-bench.git
cd dspy-security-bench

# either with uv:
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e .

# or with pip:
pip install -e .
```

Requires **Python 3.10+** and **dspy >= 3.3.0b1** (the canonical-tool-call
release that adds `dspy.ReActV2`). pip/uv handle the pre-release pin
automatically because the version is explicit in `pyproject.toml`.

## Quickstart

The full pipeline in Python:

```python
import dspy
from dspy_security_bench.synthesis.generator import synthesize_tasks
from dspy_security_bench.synthesis.validator import validate_tasks
from dspy_security_bench.optimizers import build_agent_factories
from dspy_security_bench.llm_judge import LLMJudgeMetric
from dspy_security_bench.runner import evaluate_factories, summarize

dspy.configure(lm=dspy.LM("openai/gpt-4o-mini"))

# 1. Generate a synthetic trainset grounded in the workspace suite's seed env
raw_tasks = synthesize_tasks("workspace", n=150, model="openai/gpt-4o")

# 2. Filter for validity and dedupe against real test tasks
val = validate_tasks(raw_tasks, "workspace", checks=("syntactic", "dedupe"))
trainset = val.kept  # ~100 high-quality tasks survive

# 3. Run optimizers — produces a factory per optimizer
factories = build_agent_factories(
    trainset=trainset,
    optimizers=["unoptimized", "bootstrap_fewshot", "miprov2"],
    suite_name="workspace",
    signature="query -> answer",
    metric=LLMJudgeMetric(judge_lm=dspy.LM("openai/gpt-4o-mini", temperature=0)),
)

# 4. Evaluate against AgentDojo's attack suite
df = evaluate_factories(
    factories=factories,
    suite_name="workspace",
    attacks=["direct", "important_instructions", "tool_knowledge"],
    user_task_ids=["user_task_0", "user_task_1", "user_task_3", "user_task_10"],
    injection_task_ids=["injection_task_0"],
    max_iters=10,
)

# 5. Aggregate
print(summarize(df))
```

Output shape:

```
       optimizer                 attack  utility_rate  security_rate  injection_success_rate  n_runs
0    unoptimized                 direct          0.50           0.75                    0.25       4
1    unoptimized  important_instructions          0.50           0.50                    0.50       4
2    unoptimized          tool_knowledge          0.25           0.25                    0.75       4
3  bootstrap_fewshot               direct          0.75           0.75                    0.25       4
...
```

## CLI

The synthesis and validation steps have CLIs that produce JSONL files:

```bash
# Synthesize (dry-run prints the prompt without calling the API)
dspy-security-bench-synthesize workspace --dry-run

# Real synthesis (requires OPENAI_API_KEY / ANTHROPIC_API_KEY)
export OPENAI_API_KEY=sk-...
dspy-security-bench-synthesize workspace \
    --n 150 --model openai/gpt-4o \
    --out data/synthetic_train/workspace_gpt4o_raw.jsonl

# Validate
dspy-security-bench-validate workspace \
    data/synthetic_train/workspace_gpt4o_raw.jsonl \
    --out data/synthetic_train/workspace_gpt4o.jsonl \
    --report data/synthetic_train/workspace_gpt4o_report.json
```

## Development

```bash
# install with dev extras (pytest, ruff, pytest-cov)
uv pip install -e ".[dev]"

# run the full test suite (61 tests, all offline / mocked — no API key needed)
pytest tests/ -v

# linting
ruff check dspy_security_bench/ tests/
ruff format dspy_security_bench/ tests/
```

The test suite covers env-data extraction, synthesis helpers, validator
checks, the AgentDojo wrapper (end-to-end against `user_task_0` with
`DummyLM`), the optimizer harness, the LLM-as-judge metric, and the
runner's orchestration (with `benchmark_suite_with_injections` mocked).

## Design decisions

These are documented in detail in [ARCHITECTURE.md](ARCHITECTURE.md). The key
v0.1 scope choices:

- **Synthetic trainset, not held-out split.** AgentDojo has only ~40 user tasks
  per suite — not enough for a clean train/test split that supports optimizers
  like MIPROv2. We synthesize ~100 in-distribution query-only tasks per suite
  via GPT-4o + Claude Sonnet, validated against the env, and use the real
  AgentDojo tasks unmodified as the held-out test set.
- **Query-only tasks for training; full action-task suite for testing.** Action
  tasks (send, create, modify) have hand-written utility checks that don't
  synthesize cleanly. Training on queries-only is acceptable because the
  research question is whether *prompt optimization* (not action selection)
  affects robustness.
- **Hybrid metric**: LLM-as-judge with substring fast-path for training (cheap
  + tolerant of paraphrasing); real AgentDojo `utility()` for testing
  (rigorous, the actual published benchmark).
- **Single-output signature constraint** on the DSPy program. The model's final
  output goes into AgentDojo's single `model_output` utility argument.

## Acknowledgments and prior work

This benchmark sits on top of:

- [**DSPy**](https://github.com/stanfordnlp/dspy) (Stanford NLP) — the optimizer
  framework being evaluated.
- [**AgentDojo**](https://github.com/ethz-spylab/agentdojo) (ETH Zurich, SPY lab) —
  the attack suite and task environments providing ground-truth robustness
  measurement.

It also draws on the broader 2024-26 prompt-security literature, including
[GEPA](https://arxiv.org/abs/2507.19457),
[BATprompt](https://arxiv.org/abs/2412.18196),
[Survival of the Safest](https://arxiv.org/abs/2410.09652),
[InjecAgent](https://arxiv.org/abs/2403.02691), and
[WASP](https://arxiv.org/abs/2504.18575).

## Citation

If you use this benchmark in research or production, please cite:

```bibtex
@misc{ahamed2026dspysecuritybench,
  title = {{dspy-security-bench}: Measuring optimizer-induced robustness in
           agentic DSPy programs},
  author = {Imran Ahamed},
  year = {2026},
  howpublished = {\url{https://github.com/immu4989/dspy-security-bench}},
}
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
