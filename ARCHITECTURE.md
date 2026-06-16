# Architecture

This document is the engineering map of `dspy-security-bench` — what each
module does, why it exists, and which v0.1 scope choices are deliberate.

## One-paragraph summary

`dspy-security-bench` runs three pipelines in sequence:

1. **Trainset synthesis** — generates ~100 read-only query tasks per AgentDojo
   suite, grounded in the suite's seed environment data, using one or two
   strong LLMs as generators.
2. **DSPy optimization** — runs `BootstrapFewShot`, `MIPROv2`, etc. against the
   synthetic trainset to produce a dict of named agent factories (one per
   optimizer).
3. **AgentDojo evaluation** — wraps each agent factory in a
   `DSPyReActV2Element` pipeline and runs AgentDojo's
   `benchmark_suite_with_injections` across the requested attack suite.

The output is a `pandas.DataFrame` with one row per
`(optimizer, attack, user_task, injection_task)` combination, columns
`utility` and `security`.

## Module map

```
dspy_security_bench/
├── synthesis/
│   ├── extract_env_data.py    # markdown summary of suite seed env
│   ├── generator.py           # LLM-based task synthesis
│   └── validator.py           # syntactic + dedupe + (optional) solvability
├── adapters/
│   └── agentdojo.py           # DSPyReActV2Element pipeline wrapper
├── optimizers.py              # named optimizer harness + substring metric
├── llm_judge.py               # LLM-as-judge metric (fast-path substring)
└── runner.py                  # benchmark orchestration + DataFrame
```

### `synthesis/extract_env_data.py`

Produces a compact markdown summary of an AgentDojo suite's seed env (the
state of calendar, inbox, files, etc. before any task runs). Used by:

- the synthesis generator, as prompt context grounding the LLM
- the validator, as the searchable corpus for the syntactic check

Suite-specific extractors (currently only `workspace`) emit nicer summaries;
a generic introspection fallback works for `banking`, `travel`, `slack`.

### `synthesis/generator.py`

Given a suite name and an LLM model identifier (e.g. `openai/gpt-4o` or
`anthropic/claude-sonnet-4-5` via litellm), generates a list of
`{"prompt", "ground_truth"}` dicts.

Each batch prompt contains:

- the full tool list with parameter signatures
- the env data summary (from `extract_env_data`)
- 3 real example tasks (auto-picked from `suite.user_tasks` filtering for
  interrogative read-only prompts with non-empty `GROUND_TRUTH_OUTPUT`)
- strict constraints (read-only, env-grounded, JSON output)

Supports `--dry-run` to print the assembled prompt without paying for API
calls.

### `synthesis/validator.py`

Three independent checks, each can be enabled separately:

| Check | What | Implementation |
|---|---|---|
| `syntactic` | The ground_truth string appears in the suite's env corpus (case-insensitive) | substring + multi-token fallback |
| `dedupe` | The prompt is not too similar to any real test-suite user task | sentence-transformers cosine over `all-MiniLM-L6-v2`; threshold 0.9 |
| `solvability` | A small judge LLM can produce the answer given (task, env-excerpt) | optional, costs API tokens |

Returns a `ValidationResult` with `kept`, `dropped` (each with `_reason`),
and `counts_by_reason`.

### `adapters/agentdojo.py` — `DSPyReActV2Element`

The critical bridge. Implements `BasePipelineElement.query()` so a DSPy
program can run as an AgentDojo pipeline element.

Flow per call:

1. Translate `runtime.functions` (AgentDojo `Function` objects) → `dspy.Tool`
   closures, each binding the AgentDojo `runtime` + `env`. Critically, the
   closures call `runtime.run_function(env, name, kwargs)`, which means
   attacks that mutate `env` surface naturally in tool outputs.
2. Instantiate `dspy.ReActV2` with these tools via the user-supplied
   `agent_factory`.
3. Run the agent (`agent(query=query)`).
4. Translate `result.history.messages` into AgentDojo `ChatAssistantMessage`
   and `ChatToolResultMessage` types, preserving tool call IDs.
5. Append a final `ChatAssistantMessage` with the model's output for
   AgentDojo's `utility()` to check.

**v0.1 constraints (documented for honest scope):**

- The agent's signature must have **exactly one output field**.
- Tool results are JSON-serialized for the agent (lossy for complex types).
- Tool errors surface as observation strings, not exceptions.
- The ReActV2 ID-collision bug ([dspy#9825](https://github.com/stanfordnlp/dspy/pull/9825))
  is irrelevant here because each AgentDojo task is a single `forward()` call.

### `optimizers.py`

Two responsibilities:

1. **Trainset prep** — converts `{"prompt", "ground_truth"}` dicts into
   `dspy.Example` objects with `query` as the input field.
2. **Optimizer harness** — `build_agent_factories(...)` runs each requested
   optimizer (`unoptimized`, `bootstrap_fewshot`, `miprov2`) and returns a
   dict mapping optimizer name → `agent_factory(tools, max_iters) → ReActV2`.

Training-time tools are bound to a *fresh* suite env, separate from the
test-time env. The factory we return baked in the optimized instructions
and demos; at test time the factory creates a fresh `ReActV2` with the
test-time tools and applies the optimized state.

Also exports `substring_match_metric` — the v0.1 placeholder metric.

### `llm_judge.py`

A drop-in replacement for `substring_match_metric` that uses a small LLM
(default: `openai/gpt-4o-mini`) as a judge.

Key design choices:

- **Substring fast path**: if the ground truth appears in the agent's answer,
  return 1.0 immediately without an LLM call (~60-80% of well-grounded
  synthetic tasks).
- **Single-field judge signature** (no chain-of-thought): minimizes token
  cost and parsing failure modes.
- **Graceful fallback**: on judge LLM failure (parse error, rate limit, etc.),
  falls back to the substring metric and returns its score.
- **Cacheable**: DSPy's LM uses litellm's cache, so repeated optimizer
  evaluations on the same (example, prediction) hit cache.

### `runner.py`

The orchestrator. Given a dict of factories and a list of attacks:

1. Builds an `AgentPipeline([InitQuery(), DSPyReActV2Element(factory)])` per
   factory.
2. For each `(factory, attack)` combination, calls
   `agentdojo.benchmark.benchmark_suite_with_injections(...)` which returns a
   `SuiteResults` dict keyed by `(user_task_id, injection_task_id)`.
3. Flattens `SuiteResults` into rows with explicit columns.
4. Returns a `pandas.DataFrame`.

`summarize(df)` produces the `(optimizer, attack)` aggregation:
`utility_rate`, `security_rate`, `injection_success_rate`, `n_runs`.

**Convention**: AgentDojo's `security_results[k] == True` means the injection
succeeded (bad). We expose both `injection_succeeded` (AgentDojo's
convention) and `security` (= 1 - injection_succeeded, so higher is better
and matches `utility`'s direction).

## v0.1 scope choices and why

### Why synthesize a trainset rather than split AgentDojo's tasks

AgentDojo has ~25-40 user tasks per suite. Splitting 70/30 leaves 7-12
training examples — below what BootstrapFewShot or MIPROv2 need to find a
meaningful improvement. Synthesizing 100 in-distribution tasks per suite
gives the optimizers enough signal while keeping the real AgentDojo tasks
as a clean held-out test set.

The cost: synthesis methodology becomes part of the contribution and must
be defended (we use two generator LLMs to reduce monoculture bias, and the
validator drops syntactically-invalid and duplicate tasks).

### Why query-only synthesis

AgentDojo's action tasks (send email, create event, modify file) have
hand-written `utility()` checks that inspect env-state mutations. These
checks cannot be auto-synthesized — they require domain knowledge per task.

We restrict synthesis to read-only query tasks because:

- Query utility = "answer contains ground truth string" templates trivially
- Query tasks make up ~40% of AgentDojo's real test set, so training on this
  distribution is not unreasonable
- The research question (does *prompt optimization* affect robustness?) does
  not require action-task training — robustness is mostly about parsing
  adversarial input, not about complex action selection

### Why hybrid metric (LLM-judge for train, real `utility()` for test)

- LLM-judge for training: cheap, paraphrase-tolerant, scales to optimizer
  evaluation cycles
- Real AgentDojo `utility()` for testing: rigorous, reproducible, the actual
  metric the benchmark community uses

This separation pre-empts the obvious reviewer pushback ("you trained and
tested on the same metric"). It also lets us publish strong claims about
robustness without claiming anything about the judge LLM.

### Why single-output signature

ReActV2 produces structured outputs via its `submit` tool. AgentDojo's
`utility()` takes a single `model_output` string. To bridge cleanly without
ambiguity, v0.1 requires the user's signature to have exactly one output
field. Multi-output support is a v0.2 question that needs a per-field
concatenation policy.

## Known gaps and v0.2 roadmap

- **Suite-tuned extractors** for banking, travel, slack (the generic
  fallback works but produces less compact prompts).
- **GEPA optimizer** in the harness (currently `unoptimized`,
  `bootstrap_fewshot`, `miprov2`).
- **Action-task synthesis** with synthesized utility checks (hard — likely
  needs LM-generated `expected_final_state` and a separate state-diff
  judge).
- **Multi-output signature support**.
- **Action-aware attacks** in the report (currently aggregated across all
  attack types).
- **Notebook tutorials** (`docs/tutorial/`) — a v0.1 README-quickstart-style
  notebook is the next planned artifact.
- **TMLR submission** — if v0.1 findings are publishable, the next step is a
  short empirical paper. The benchmark methodology is described here; the
  paper would add a comprehensive empirical sweep across all 4 suites and a
  qualitative analysis of optimizer-induced robustness mechanisms.

## Repository layout

```
.
├── dspy_security_bench/        # the package
│   ├── synthesis/
│   ├── adapters/
│   ├── optimizers.py
│   ├── llm_judge.py
│   └── runner.py
├── tests/                       # pytest suite (planned, v0.2)
├── data/                        # generated synthetic trainsets (git-ignored)
├── scripts/                     # one-off scripts / smoke tests
├── docs/                        # tutorials (planned, v0.2)
├── README.md
├── ARCHITECTURE.md              # this file
├── LICENSE
└── pyproject.toml
```
