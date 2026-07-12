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

Exit code: `0` pass · `1` gate failed · `2` could not run.

## 3. Two gate modes

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
```

Now a PR that bumps the model and loses safety fails the check, with the drop
named in the finding.

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
