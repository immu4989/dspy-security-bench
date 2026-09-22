# Start here

Choose one workflow and prove it works with a small local example before
connecting production data or a live agent. The project has many specialized
protocols; you do not need to adopt them all.

## Developers: test your agent

For a credential-free introduction **on main**, run
`dspy-security-bench scan demo --out fictional-scan-review` from a source install.
Open its `review.html`, then follow the included replay commands. These are
invented outcomes, not model measurements. The [scan evidence guide](scan-evidence.md)
then covers capturing real evidence, pinning a reviewed plan, and checking an
upgrade without paying to rerun its models.

Install the published package with `python -m pip install dspy-security-bench`.
Run `dspy-security-bench init --agent mypackage:build_agent`, then
`dspy-security-bench scan --config .dspy-security-bench.yaml --plan` to inspect
the test matrix before invoking a model. A live scan needs your framework,
provider credentials, and a safe test environment; model calls can cost money.

Start with the [agent integration guide](integrations.md) and the
[README CI quickstart](../README.md#five-minute-ci-quickstart). Do not point a
test agent at production tools with write privileges merely to try the demo.

## Security and procurement teams: review suppliers

From a source checkout, use the [supplier portfolio guide](ai-supplier-portfolio.md)
to review supported CycloneDX and SPDX AI disclosures under your own policy.
Start with the committed fictional sources. Then replace them with a small,
authorized supplier submission and review the findings with its owner.

Output is a reproducible structural review, not a supplier ranking. A missing
input is not a pass, and a populated field is not proof that its value is true.

## Public-sector and enterprise evaluators: build a reviewable case

From the source checkout, run:

```bash
dspy-security-bench assure demo --out-dir artifacts/first-review
```

Open `artifacts/first-review/index.html`. Inspect the source JSON and claim
statuses. The [AssuranceGraph guide](assurancegraph.md) explains how to supply
your own case and independently verified evidence. The [federal guide](federalproof.md)
describes standards-aligned assessment inputs and their limits.

These tools do not provide an authorization to operate, a legal compliance
determination, or a guarantee of safety. Evidence owners and accountable
reviewers retain those decisions. Do not upload restricted operational records
to public issue trackers or evidence registries.

## Researchers: reproduce, challenge, or extend

Read the [leaderboard](../LEADERBOARD.md),
[research pipeline](../README.md#research-pipeline-quickstart), and
[research audit](research-audit-2026-08.md). Preserve unfavorable results and
runtime failures. Distinguish synthetic demonstrations from measured external
systems, and identify the exact revision, inputs, model settings, and limitations.

Useful contributions include independent reproductions, bounded importer
fixtures, adversarial verifier tests, and worked integrations. See
[CONTRIBUTING](../CONTRIBUTING.md) before submitting.

## Which installation should I use?

The published release and repository main branch are different surfaces. Features
marked **On main** and the Unreleased changelog may not be on PyPI yet. Use the
[source installation instructions](../README.md#try-a-local-evidence-review)
for those workflows; pin a reviewed commit for reproducible organizational use.
Do not assume a published version contains a command merely because the main
branch documentation describes it.

Existing scan users should follow the [upgrade checklist](scan-upgrade-guide.md)
for measurement protocols, retained baselines, reviewed plan pins, and CI gates.

For development, install `python -m pip install -e ".[dev]"` inside your virtual
environment and run `python -m pytest`. Optional framework and signing extras
are listed in [pyproject.toml](../pyproject.toml); install only what your chosen
workflow needs.
