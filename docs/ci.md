# CI gate: catch injection-safety regressions in a PR

`dspy-security-bench scan` runs the injection benchmark against your agent,
applies a pass/fail policy, and exits non-zero when the agent is unsafe — so
CI blocks the merge. It renders findings to your terminal, to JSON, and to
**SARIF**, which GitHub ingests natively into the Security tab.

The motivating case is a real one this benchmark documented: upgrading a base
model can *silently collapse* injection-safety (Mistral Small → Mistral Large
went from 100% to 0% injection-security). A capability benchmark would call
that upgrade an improvement. This gate catches it.

## 1. Configure

On main, configuration is strict: keys must be known, sections must be mappings,
and duplicate YAML keys are rejected, including conflicting YAML merge overrides.
Files must be valid UTF-8 and at most 1 MB. Thresholds must be numeric (not quoted
strings or booleans), and selection/format lists must be nonempty and unique.
Misspelled settings fail before a model is constructed rather than falling back
to a different policy.

Generate the config and workflow in one command:

```bash
dspy-security-bench init --model openai/gpt-4o-mini
# Or wrap your application agent:
dspy-security-bench init --agent mypkg.agents:build
```

Existing files are never overwritten unless you pass `--force`. You can also
copy the templates manually:

Copy [`examples/.dspy-security-bench.yaml`](../examples/.dspy-security-bench.yaml)
to your repo root and point it at your agent — either a model (uses the
built-in function-calling agent) or your own `Agent` factory:

```yaml
agent:
  model: openai/gpt-4o-mini          # or:  import: mypkg.agents:build
scan:
  suites: [workspace]
  attacks: [direct, important_instructions]
  user_tasks: 5
gate:
  mode: absolute
  min_security: 0.90
report:
  formats: [terminal, sarif]
fail_on: error
```

## 2. Run locally

```bash
pip install dspy-security-bench
export OPENAI_API_KEY=sk-...
dspy-security-bench scan --config .dspy-security-bench.yaml
```

Before using an API key, inspect the exact matrix at no cost:

```bash
dspy-security-bench scan --config .dspy-security-bench.yaml --plan
```

The plan resolves suite-specific task IDs and reports the total benchmark
cases. `user_tasks` and `injection_tasks` each accept a positive count or
`"all"`.

Exit code: `0` pass · `1` gate failed · `2` could not run.

On main, exit 0 means **not blocked by the configured enforcement policy**, not
necessarily that every requirement was met. JSON adds `requirements_met` and
`enforcement_status` (`requirements_met`, `non_blocking_shortfalls`, `blocked`).
The legacy `passed` field continues to describe enforcement for compatibility.
For example, `fail_on: never` preserves unfavorable findings but exits 0; the
terminal labels this `NON-BLOCKING SHORTFALLS`, not `PASS`. The same distinction
applies to warnings when enforcement is limited to errors. SARIF run properties
retain both outcomes. For strict acceptance, inspect `requirements_met`, not
just the process exit status.

## 3. Two gate modes

### Sample size and uncertainty (on main)

By default the absolute gate compares the observed rate (`statistic: point`).
You can require a minimum number of observations per suite/agent/defense/attack
cell and opt into the lower endpoint of a **two-sided** Wilson score interval:

```yaml
gate:
  mode: absolute
  min_security: 0.90
  min_runs: 35
  statistic: wilson_lower
  confidence: 0.95
fail_on: warning
```

At this confidence level, 5/5 resisted observations have a lower bound near
56.6%; 35/35 have one near 90.1%. These are binomial sensitivity summaries, not
guaranteed population coverage: fixed benchmark cases can be dependent and
unrepresentative. The calculation does not adjust for multiple cells, model
selection, optional stopping, or adaptive adversaries. Predeclare your scope
and policy rather than repeatedly extending a run until a bound passes.
The [NIST statistical handbook](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm)
describes the Wilson method. This feature does not turn the scan into a
statistical certification or a deployment approval.

Use `--plan-json plan.json` to inspect per-cell feasibility before execution.
An infeasible sample minimum or Wilson threshold produces an execution error
before an agent is constructed, even if perfect resistance would be observed.
This check is not a power analysis or a prediction. Adding defenses does not
increase the observations within another defense's cell. Auxiliary utility
runs do not count toward its sample size.

`min_runs` defaults to 1 and accepts integers up to one million. `confidence`
accepts 0.5 through 0.9999; count-backed Wilson evaluation supports at most one
billion observations per cell. CLI overrides are `--min-runs`, `--statistic`,
and `--confidence`. Wilson gating is absolute-only: the existing rate-only
regression baselines do not support a paired or two-sample uncertainty test.
Missing sample coverage and uncertainty shortfalls have separate SARIF rules;
neither is mislabeled as an observed successful prompt injection. They are
errors, not warnings, regardless of `warn_margin`. Explicit `fail_on: never`
still makes findings non-blocking, but does not bypass infeasible preflight.
The runner retains integer `security_successes`; Wilson API callers must supply
these counts, not reverse-engineer them from rounded rates.

### Observed-rate comparisons

**Absolute** — fail if any cell's injection-security is below `min_security`.
Good for a hard floor ("our agent must resist ≥ 90% of these attacks").

**Regression** — fail if security drops more than `max_regression` below a
committed baseline. This is the model-upgrade guard. Generate the baseline on
your main branch and commit it:

```bash
dspy-security-bench scan --config .dspy-security-bench.yaml \
    --write-baseline .dsb-baseline.json
git add .dsb-baseline.json && git commit -m "chore: injection-safety baseline"
```

Then set the gate to compare against it:

```yaml
gate:
  mode: regression
  baseline: .dsb-baseline.json
  max_regression: 0.10
  require_baseline_coverage: true
```

Now a PR that bumps the model and loses safety fails the check, with the drop
named in the finding.

On main, a measured cell missing from the baseline fails by default. This
corrects the earlier informational-only behavior, which could report a pass
without any regression comparison. Coverage gaps use a separate SARIF rule;
they are not claims that prompt injection succeeded. An organization that
deliberately wants informational-only missing cells can set
`gate.require_baseline_coverage: false`; JSON metadata still records the gap.
`fail_on: never` remains a general explicit non-blocking mode.

Cells are matched by exact suite, agent name, defense, and attack. When comparing
model revisions, keep a stable owner-selected `agent.name` in both runs; do not
silently compare differently named agents. Review and pin the baseline through
your normal change process. A baseline file is not authenticated by this tool.

Empty summaries, duplicate cells, non-finite/out-of-range rates, nonpositive or
fractional run counts, malformed baselines, and non-boolean coverage settings
are errors (exit 2), even in non-blocking mode. Baselines are validated before
model invocation. Missing thresholds serialize as JSON `null`, never `NaN`.
Baseline generation applies the same measurement checks before writing.

New CLI-generated baselines use schema version 2 and bind the resolved task IDs,
their order, attack-specific injection selections, defenses, stable agent name,
AgentDojo distribution version, and measurement protocol. `all` is expanded into
actual IDs for the pin. A different scope is rejected before agent construction,
even when cell names or aggregate rates happen to match. The model identifier
is deliberately not pinned when you supply a stable `agent.name`, allowing the
intended model-upgrade comparison.

Legacy rate-only baselines remain readable but print a warning and report
`baseline_scope_verified: false`; regenerate them to obtain scope binding.
Direct `evaluate_gate` callers using a v2 baseline must supply `scan_scope`.
This digest is not a signature, does not hash every dependency or task source
file, and does not establish statistical equivalence. Pin your reviewed code,
environment, evaluator, and inputs separately. Do not overwrite a baseline just
to make an unexpected scope-change error disappear.

The runner also checks raw observation completeness before aggregation. Missing
security observations are not treated as resisted attacks, and pandas cannot
silently exclude missing measurements from the mean. Every requested user/task
pair must be returned with boolean utility and injection-success outcomes.
AgentDojo's DoS attack convention intentionally uses one injection task and is
handled separately. These checks detect missing data; they do not prove the
evaluator's observations are accurate or distinguish every upstream runtime
failure that AgentDojo itself represents as an outcome.

`--plan` validates supported attack/defense names and rejects duplicate matrix
selections without constructing an agent. Its scored-case count respects the
single-injection DoS convention, including when mixed with ordinary attacks.
Additional injection-task utility runs are listed separately: they can also
invoke the agent, but are not scored user/injection pairs. Neither number is a
token-price quote; tool loops, retries, and provider behavior affect actual cost.

For a machine-readable preflight artifact:

```bash
dspy-security-bench scan --config .dspy-security-bench.yaml \
  --plan-json scan-plan.json
```

This command exits without constructing an agent, even without `--plan`. It
requires a new output file and an existing parent directory. The JSON binds the
scope and gate settings, records scored/auxiliary counts separately, and labels
itself as a plan rather than executed evidence. Review labels before sharing.
Normal scan output paths are checked before execution: JSON and SARIF cannot
share a file, alias each other, be symbolic links, or overwrite the input config
or comparison baseline. Explicit `--write-baseline` remains the intentional
baseline-update path; review changes through version control.

## 4. GitHub Action

Copy [`examples/injection-scan.yml`](../examples/injection-scan.yml) to
`.github/workflows/injection-scan.yml`. It installs the tool, runs the scan,
and uploads SARIF to the Security tab. Add your provider API keys as repo
secrets. Findings appear inline on the PR; a failing gate blocks merge.

## 5. Standards mapping

SARIF findings are tagged with one rule mapped to **OWASP LLM01 (Prompt
Injection)**, with **NIST AI 100-2** and **MITRE ATLAS** references in the
rule's property bag — so the results slot into an existing AppSec or federal
compliance workflow.

## Keeping it cheap

A CI gate must be fast. The defaults (1 suite, 2 attacks, 5 user tasks,
undefended) run in a few minutes for ~$1–2 of LM calls. Widen `suites`,
`attacks`, and `user_tasks` for a more thorough (and more expensive) gate;
narrow them for a quick smoke on every PR and a full run nightly.

## What a PASS does and does not mean

The scan tests a **fixed set of known attacks**. A PASS means the agent
resisted those specific attacks at the configured scale. It is **not** a
guarantee against an adaptive adversary who knows your defenses. Treat the
gate as a regression detector and a floor, not a certificate of safety. Every
report repeats this; it is load-bearing, not boilerplate.
