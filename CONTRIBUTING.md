# Contributing

Contributions are welcome. The most useful ones, roughly in order:

1. **Adding a model to the leaderboard** — see below.
2. **Proposing a public-interest ImpactTwin domain** — grants, benefits,
   utilities, health administration, supply chain, emergency management, or a
   commercial workflow with a clearly affected stakeholder.
3. **Adding an attack or a defense** to the harness.
4. **Reporting a measurement you cannot reproduce.** This is genuinely valuable;
   every published row ships with the result JSON that produced it, so
   disagreements should be resolvable.
5. Bug reports and documentation fixes.

## Getting set up

```bash
git clone https://github.com/immu4989/dspy-security-bench
cd dspy-security-bench
uv pip install -e ".[dev]"

pytest tests/ -v          # all offline, no API key needed
ruff check dspy_security_bench/ tests/
```

The test suite does not make network calls. You only need provider API keys to
run the benchmark itself.

## Adding a model to the leaderboard

Numbers are never taken on faith. Open an **Add model** issue with the pinned
model id, and the maintainer runs the frozen protocol and commits the result
JSON alongside the row. If you want to run it yourself first:

```bash
uv run python scripts/run_leaderboard.py --model <model_id> --headline-only
uv run python scripts/generate_leaderboard.py    # regenerates LEADERBOARD.md
```

Two rules that exist to keep rows comparable:

- **Pin the model id.** Never a `-latest` alias — a row has to mean one thing
  permanently.
- **Do not hand-edit `LEADERBOARD.md`.** It is generated from
  `leaderboard/results/*.json`; editing it directly lets the board drift from
  the data behind it.

## Changing the measurement protocol

`leaderboard/protocol.yaml` is a frozen contract. Anything under its `frozen:`
block — suites, attack, scaffold, decoding settings, task subset — determines
what every published number means. Changing any of it:

- invalidates every existing row, which must be re-measured;
- moves the config hash recorded in each result;
- requires a `protocol_version` bump.

Presentation, the model registry, and thresholds can change without a re-run.
If you are proposing a protocol change, please open an issue first so the
re-measurement cost can be discussed before the work happens.

## Proposing an ImpactTwin public-interest domain

ImpactTwin domains pair an ordinary workflow with a poisoned twin so the causal
effect of untrusted content is measurable. Start with the **Public-interest twin**
issue form rather than a large pull request. A strong proposal identifies:

- the people or institutions affected by a bad agent action;
- the untrusted input and the economically or mission-relevant sink;
- which structured facts remain identical across the twins;
- the live state invariant that can be validated without an LLM judge;
- a bounded consequence measure that will not be misrepresented as predicted
  loss; and
- primary standards or public guidance that explain why the control matters.

Accepted implementations must use synthetic organizations and data, run fully
offline with deterministic reference fixtures, score utility separately from
security, emit versioned machine-readable evidence, and include explicit
non-certification language. Do not submit real proposal data, personal data,
credentials, vulnerabilities in a production agency system, or claims that a
benchmark result establishes legal compliance.

Changes to a frozen ImpactTwin scenario require a scenario-version update. The
protocol hash will move automatically, but the version bump ensures humans do
not compare semantically different runs.

## Statistical conventions

Two are load-bearing and easy to get wrong. Both are explained in
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md):

- **Report utility alongside security.** A model that fails at everything also
  fails the attacker's goal, so a security number on its own is not
  interpretable.
- **Bootstrap over task pairs, not over pooled repeats.** At temperature 0 the
  repeats are technical replicates; treating them as independent samples shrinks
  every interval by roughly √k.

## Code style

- `ruff` for linting and formatting; CI enforces it for the package and tests.
- Comments should explain *why*, particularly where a choice is non-obvious or
  where a previous approach was wrong.
- New behaviour needs a test. Tests must run offline.

## Reporting a security issue in the harness

This project studies attacks, so a bug here is not usually sensitive. If you
believe you have found something that should not be public, open an issue asking
for a private channel rather than posting details.

## Maintainer releases

Releases are built, checked, and published from a `vX.Y.Z` tag. See
[`docs/releasing.md`](docs/releasing.md) for the one-time PyPI Trusted Publisher
setup and the release checklist. Do not upload a wheel from a local machine.

## Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
