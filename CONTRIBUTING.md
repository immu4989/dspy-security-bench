# Contributing

Contributions are welcome. The most useful ones, roughly in order:

1. **Submitting a ProofRun result for your own agent** — produce recomputable,
   provenance-labeled evidence and open a pull request; see below.
2. **Submitting a real control experiment** — publish policy-off/policy-on
   evidence even when the outcome is mixed or negative; see below.
3. **Improving a native framework bridge** — reproduce an upstream SDK change,
   add a zero-provider-call compatibility test, and keep the benchmark contract
   framework-neutral; see below.
4. **Adding a model to the base-model leaderboard** — see below.
5. **Proposing a public-interest ImpactTwin domain** — grants, benefits,
   utilities, health administration, supply chain, emergency management, or a
   commercial workflow with a clearly affected stakeholder.
6. **Adding an attack or a defense** to the harness.
7. **Reporting a measurement you cannot reproduce.** This is genuinely valuable;
   every published row ships with the result JSON that produced it, so
   disagreements should be resolvable.
8. Bug reports and documentation fixes.

## Getting set up

```bash
git clone https://github.com/immu4989/dspy-security-bench
cd dspy-security-bench
uv pip install -e ".[dev]"

pytest tests/ -v          # all offline, no API key needed
ruff check dspy_security_bench/ tests/
```

The test suite does not make network calls. You only need provider API keys to
run the benchmark itself. Contributors changing embedding-based synthesis or
deduplication should install `.[dev,synthesis]`; the ordinary development and
CI environment intentionally avoids the large optional ML runtime.

## Adding or updating a framework bridge

Open a **Framework integration** issue before a large adapter change. Native
bridges live in `dspy_security_bench/integrations/` and must preserve four
invariants:

- pass the exact live `BenchTool` callable into the framework rather than a
  simulated tool;
- return the framework's final answer through `AgentResult` and retain any real
  tool-call ledger;
- import optional SDKs lazily so the base package remains lightweight; and
- make no provider call in compatibility tests.

Add the dependency as an optional extra, update the integration guide, and add
its current SDK surface to `tests/test_framework_compat.py`. The scheduled
framework matrix installs each extra independently, which keeps transitive
dependencies from hiding a missing declaration. If an upstream SDK has a Python
version boundary, encode and document it instead of allowing an opaque import
failure.

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

## Submitting your agent's ProofRun result

The recommended path is the versioned reusable workflow in
[`docs/proofrun.md`](docs/proofrun.md). It preserves and attests the result even
when the confidence gate fails. A local, self-attested bundle can be produced
with the same CLI contract:

```bash
dspy-security-bench proofrun run \
  --agent your_package.security:build_agent \
  --trials 10 \
  --submitter "@your-handle" \
  --agent-source "https://github.com/you/your-agent" \
  --out submissions/impact/your-agent.json
dspy-security-bench proofrun verify submissions/impact/your-agent.json --offline
```

Commit only the generated bundle under `submissions/impact/`. Pull-request CI
recomputes every rate, interval, outcome class, usage total, and content digest.
Five trials are the minimum; ten is the recommended default. Do not hand-edit a
bundle after generation.

Offline verification establishes internal consistency and protocol identity.
Online ProofRun verification additionally checks a GitHub artifact attestation,
source commit, ref, runner environment, and workflow identity. It still cannot
make a remote provider response independently observable. Never include API
keys, private system prompts, customer data, or production tool results.

## Submitting control-effectiveness evidence

Use the dual-mode trusted builder documented in
[`docs/control-evidence-registry.md`](docs/control-evidence-registry.md), or run
`dspy-security-bench proofrun control` locally. Commit only the generated JSON
under `submissions/control/` with a lowercase kebab-case filename.

Control entries must preserve at least five paired trials, use a fresh agent for
every case and condition, have zero runtime errors, and leave argument capture
disabled. Agent and policy source URLs must be public HTTPS links. The exact
normalized policy and its SHA-256 identity are part of the evidence.

A weak or failing policy is welcome when its evidence is valid. Do not tune or
filter submissions merely to remove unfavorable trials; explain the limitation
in the pull request. Registry review checks recomputability, scope, redaction,
and provenance—it does not award a safety or compliance certification.

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

Three are load-bearing and easy to get wrong. They are explained in
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md):

- **Report utility alongside security.** A model that fails at everything also
  fails the attacker's goal, so a security number on its own is not
  interpretable.
- **Base leaderboard: bootstrap over task pairs, not pooled repeats.** At temperature 0 the
  repeats are technical replicates; treating them as independent samples shrinks
  every interval by roughly √k.
- **RepeatTwin: report each pair across stochastic trials.** Wilson intervals use
  `fixed_suite_pair_trial` observations and describe variation on the five
  frozen pairs only. They are not uncertainty over an unseen task population.

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
