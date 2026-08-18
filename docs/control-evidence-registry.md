# Open Control Evidence Registry

The Open Control Evidence Registry is a public, fork-to-contribute ledger of
repeated AI-agent control experiments. It answers a practical question that a
policy document, product badge, or single benchmark score cannot answer:

> When the same agent faces the same poisoned mission, what changes when this
> exact enforcement policy is turned on—and how stable is that change?

Each submission binds the complete RepeatControlTwin evidence tree to the exact
policy document, its SHA-256 identity, public agent and policy source links,
uncertainty estimates, and optional GitHub/Sigstore workflow provenance. Anyone
can recompute the result offline without model credentials.

The registry is not a certification program. It is open measurement
infrastructure for comparing evidence and finding residual risk.

## Why this is useful

- **Public agencies and acquisition teams** can request a portable synthetic
  control experiment from vendors, inspect its limitations, and rerun it before
  connecting an agent to procurement or administrative systems.
- **AI vendors and startups** can answer repeated customer due-diligence
  questions with one inspectable artifact rather than screenshots and bespoke
  spreadsheets.
- **Enterprise security teams** can compare a control revision against its own
  previous evidence while keeping containment, mission recovery, and clean
  utility separate.
- **Researchers and maintainers** can publish negative results. A valid but
  ineffective policy remains eligible, which reduces the incentive to hide
  failures and makes control design more cumulative.
- **Users and civil-society reviewers** get a plain JSON trail from raw tool
  events to public claims instead of an opaque safety label.

Better reusable evidence can reduce duplicated evaluation work and shorten the
path from security review to responsible deployment. The synthetic dollar
values in ProcureBench are scenario context, however—not predicted savings,
loss, or economic impact.

## Fastest path: trusted control ProofRun

Add a workflow to the repository containing the agent and policy:

```yaml
name: Control effectiveness evidence

on:
  workflow_dispatch:

permissions:
  contents: read
  id-token: write
  attestations: write

jobs:
  control-evidence:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.11.0
    with:
      evidence-kind: control
      agent: myapp.security:build_agent
      policy: policies/production.yaml
      trials: 10
      min-containment-lower-bound: 0.70
      min-clean-preservation-lower-bound: 0.80
      max-unstable-pairs: 1
      submitter: "@your-handle"
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

`policy` is a repository-relative YAML path. The workflow defaults its public
policy source to that path at the exact evaluated commit. If your policy is
published elsewhere, set `policy-source` to its immutable HTTPS URL. Use
`approval-handler: package.module:callable` when the policy has approval rules.

The evaluation job receives provider credentials. A separate clean job receives
only the generated bundle, recomputes the complete evidence tree, and attests
the exact JSON. The statistical gate is enforced after preservation, so failed
runs remain available for diagnosis.

## Local path and shareable evidence card

```bash
dspy-security-bench proofrun control \
  --agent myapp.security:build_agent \
  --policy policies/production.yaml \
  --policy-source "https://github.com/you/agent/blob/COMMIT/policies/production.yaml" \
  --approval-handler myapp.approvals:review_tool_call \
  --trials 10 \
  --min-containment-lower-bound 0.70 \
  --min-clean-preservation-lower-bound 0.80 \
  --max-unstable-pairs 1 \
  --submitter "@your-handle" \
  --agent-source "https://github.com/you/agent/tree/COMMIT" \
  --out control-evidence.json \
  --report-out repeat-control.json \
  --card-out control-evidence.svg
```

The command writes the JSON and SVG before applying configured gates. A local
run is content-addressed and self-attested. It becomes GitHub-attested only when
the exact JSON is signed in GitHub Actions and the signature is verified.

Verify locally without network access:

```bash
dspy-security-bench proofrun verify control-evidence.json --offline
```

Or verify integrity and GitHub/Sigstore provenance together:

```bash
dspy-security-bench proofrun verify control-evidence.json
```

If a team already has a RepeatControlTwin report, it can package and render it
without rerunning the model:

```bash
dspy-security-bench impact control-submit repeat-control.json \
  --submitter "@your-handle" \
  --agent-source "https://github.com/you/agent/tree/COMMIT" \
  --policy-source "https://github.com/you/agent/blob/COMMIT/policy.yaml" \
  --out control-evidence.json

dspy-security-bench impact control-card control-evidence.json \
  --out control-evidence.svg
```

## Admission contract

The public dashboard only compares bundles that pass all of these checks:

1. the canonical bundle digest and nested report digest match;
2. every ControlTwin child digest, policy identity, raw outcome, summary,
   interval, paired transition, usage total, and schedule recomputes;
3. at least five complete policy-off/policy-on trials are preserved;
4. every case and condition receives a fresh agent instance;
5. no benchmark case ended in a runtime error;
6. tool arguments were not captured in the public artifact; and
7. the agent is not one of the deterministic `reference-*` scorer fixtures.

There is deliberately no score threshold. A policy that contains 20% of harms,
recovers no missions, or damages clean utility can still be valid registry
evidence. The dashboard sorts by verified chain of custody first and a metric
lower bound second; that ordering is navigation, not an endorsement.

Use only synthetic data. Never submit credentials, customer records, restricted
acquisition information, private prompts, or production tool output.

## Evidence object and trust ladder

The packaged JSON Schema is
[`control-submission-bundle.schema.json`](../dspy_security_bench/schemas/control-submission-bundle.schema.json).
The outer bundle contains:

- public submitter, agent-source, and policy-source metadata;
- producer runtime metadata;
- the complete recomputable RepeatControlTwin report;
- separate report and bundle SHA-256 identities; and
- optional bounded GitHub Actions provenance.

Evidence tiers mean:

| Tier | Established | Still not established |
|---|---|---|
| `self_attested` | Internal consistency and content identity | Who executed the agent |
| `github_attested` | Exact bytes, caller workflow, commit, and hosted runner | Independence of caller-controlled logic |
| `trusted_builder` | Versioned central workflow and clean verification job | Independent observation of hosted-model output |
| `maintainer_reproduced` | Maintainers independently reran and recorded the evidence digest | Generalization beyond the fixed scenarios |

The site never upgrades a self-declared provenance claim. Cryptographic tiers
appear only after the exact bundle digest is recorded in the reviewed
`submissions/attestations.json` registry. Reproductions are similarly keyed by
digest rather than mutable product names.

## Submit to the public ledger

1. Fork the repository.
2. Add the generated JSON under `submissions/control/lowercase-kebab-name.json`.
3. Run `dspy-security-bench proofrun verify FILE --offline`.
4. Open a pull request with the agent and policy source links, execution cost,
   and any relevant limitations.

Submission CI validates Impact and Control evidence with the locked package
environment. See [`submissions/control/README.md`](../submissions/control/README.md)
and [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the review contract.

## Interpretation limits

- Results cover repeated executions of five fixed synthetic ProcureBench pairs,
  not all government, commercial, or user workflows.
- Wilson intervals quantify execution variability for this suite; shared
  provider drift can violate the exchangeability assumption.
- Alternating order reduces systematic order bias but is not randomization or
  blinding.
- In-process policy evidence does not prove that a separately deployed gateway
  enforced the same policy.
- GitHub provenance proves workflow and artifact identity, not provider honesty
  or model identity.
- Containment is not recovery, statistical significance is not operational
  sufficiency, and synthetic exposure is not predicted loss.

The registry's claim is narrow but useful: **control-effectiveness claims should
travel with raw, recomputable, policy-bound evidence and an explicit chain of
custody.**
