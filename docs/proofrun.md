# ProofRun: verifiable evidence for AI-agent security evaluations

Most agent benchmarks end at a score in a log. ProofRun turns a RepeatTwin or
RepeatControlTwin run into a portable evidence passport: raw trial outcomes,
uncertainty, protocol and policy identity, source commit, workflow identity,
and a cryptographic attestation over the exact JSON bytes.

ProofRun is designed for teams that need to answer two separate questions:

1. **Is this result internally reproducible?** Offline verification recomputes
   every rate, Wilson interval, outcome class, usage total, protocol hash, and
   content digest from the preserved trials.
2. **Where did these bytes come from?** GitHub artifact attestations bind the
   bundle to a repository, commit, ref, workflow run, and hosted-runner identity.

Those properties make evidence easier to exchange between an AI vendor, a
customer, an auditor, and a public-sector procurement team without pretending
that workflow provenance is a safety or compliance certificate.

## Who this serves

- **Public agencies and acquisition teams** get a machine-readable, synthetic
  test artifact whose protocol, source commit, uncertainty, and chain of custody
  can be inspected without receiving vendor credentials or restricted data.
- **AI vendors and startups** get one portable workflow for producing evidence
  customers can independently recompute, reducing bespoke security
  questionnaires and repeated integration work.
- **Enterprise security teams** get a regression gate that preserves failed
  evidence for incident analysis instead of discarding the most useful run.
- **Researchers and users** get raw trials, honest limitations, and a forkable
  path to challenge, reproduce, or extend a published result.

This supports better technical due diligence and faster adoption; it does not
replace an agency's acquisition process, an organization's risk assessment, or
provider-side audit evidence. It directly supports NIST's stated direction for
[reproducible agent-evaluation probes and machine-readable audit trails](https://www.nist.gov/programs-projects/building-evaluation-probes-agentic-ai).

## Fastest path: the trusted reusable workflow

Add this workflow to the repository containing the agent:

```yaml
name: Agent security evidence

on:
  workflow_dispatch:
  pull_request:

permissions:
  contents: read
  id-token: write
  attestations: write

jobs:
  proofrun:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.11.0
    with:
      agent: myapp.security:build_agent
      trials: 10
      min-lower-bound: 0.80
      submitter: "@your-handle"
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

The callable must take no arguments and return a fresh framework-neutral
`Agent`. The workflow checks out the evaluated commit, installs it in an
isolated Python environment, installs the immutable v0.11.0 ProofRun engine last,
runs the five clean/poisoned procurement pairs repeatedly, and preserves the
bundle even when the statistical gate fails. It then creates GitHub/Sigstore
build provenance and uploads the exact file as a workflow artifact.

Pin the reusable workflow to a release tag or full commit SHA. Do not use
`@main` for evidence you expect another organization to rely on.

### Control-effectiveness mode

Use the same trusted builder to evaluate an exact enforcement policy rather
than the agent alone:

```yaml
jobs:
  control-evidence:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.11.0
    with:
      evidence-kind: control
      agent: myapp.security:build_agent
      policy: policies/production.yaml
      approval-handler: myapp.approvals:review_tool_call
      trials: 10
      min-containment-lower-bound: 0.70
      min-clean-preservation-lower-bound: 0.80
      max-unstable-pairs: 1
```

The builder runs paired policy-off/policy-on trials, binds the normalized policy
and digest, keeps containment, mission recovery, and clean utility separate,
and generates an SVG evidence card beside the attested JSON. `policy` must be a
repository-relative path. Its public source defaults to the caller's exact
commit, or can be set explicitly with `policy-source`.

See the [Open Control Evidence Registry](control-evidence-registry.md) for the
admission and public-submission contract.

## Flexible path: the composite action

Use the action when an existing job needs custom setup before evaluation:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
  - uses: immu4989/dspy-security-bench@v0.11.0
    with:
      agent: myapp.security:build_agent
      trials: "10"
      min-lower-bound: "0.80"
```

This path is cryptographically tied to the caller's workflow. It earns the
`github_attested` evidence tier, while the centrally controlled reusable
workflow can earn `trusted_builder`.

## Local run and verification

```bash
dspy-security-bench proofrun run \
  --agent myapp.security:build_agent \
  --trials 10 \
  --min-lower-bound 0.80 \
  --submitter "@your-handle" \
  --agent-source "https://github.com/you/your-agent" \
  --out proofrun.json

# Recompute all evidence without network access.
dspy-security-bench proofrun verify proofrun.json --offline

# Verify the exact bytes and GitHub/Sigstore provenance.
gh auth login
dspy-security-bench proofrun verify proofrun.json

# Require the centrally controlled reusable-workflow identity.
dspy-security-bench proofrun verify proofrun.json --require-trusted-builder
```

Online verification rejects self-hosted-runner attestations by default. A
reviewer can opt in with `--allow-self-hosted-runner`, but should separately
evaluate that runner's trust and isolation.

For policy-effectiveness evidence, use `proofrun control`. The bundle and card
are written before any configured statistical gate is enforced:

```bash
dspy-security-bench proofrun control \
  --agent myapp.security:build_agent \
  --policy policies/production.yaml \
  --policy-source "https://github.com/you/agent/blob/COMMIT/policies/production.yaml" \
  --trials 10 \
  --min-containment-lower-bound 0.70 \
  --submitter "@your-handle" \
  --agent-source "https://github.com/you/agent/tree/COMMIT" \
  --out control-evidence.json \
  --card-out control-evidence.svg
```

## Evidence ladder

| Tier | What is established | What is not established |
|---|---|---|
| `self_attested` | Content digest and fully recomputable statistics | Who executed the agent |
| `github_attested` | Exact bytes came from a named GitHub workflow, source commit, and hosted runner | Independence of the caller-controlled workflow |
| `trusted_builder` | The attested run used the versioned DSPy Security Bench reusable workflow | Independent observation of the model provider's response |
| `maintainer_reproduced` | Maintainers repeated the result and recorded the matching bundle digest | Generalization beyond the frozen scenarios |

`submissions/reproductions.json` is the content-addressed maintainer registry.
It references accepted bundle digests rather than mutable display names.
`submissions/attestations.json` separately records cryptographically checked
GitHub tiers. A declared workflow URL alone is displayed as “attestation
pending” until that digest is in the verified registry.

## Trust boundary and limitations

ProofRun deliberately makes narrow claims:

- The attestation authenticates workflow provenance and exact evidence bytes.
- The bundle authenticates its own internal consistency through canonical
  hashing and offline recomputation.
- Secrets are never copied into provenance. Only a bounded set of public GitHub
  context fields is captured.
- A workflow cannot make a remote model provider independently observable. A
  malicious repository can substitute an agent or mock a provider before the
  trusted workflow calls it. Source review, provider-side receipts, confidential
  computing, and independent reproduction are complementary controls.
- Results describe repeated executions over five committed synthetic
  ProcureBench pairs. They do not estimate all procurement tasks and are not a
  legal, acquisition, safety, or regulatory certification.

The design follows GitHub's artifact-attestation model: an OIDC identity signs
an in-toto statement through Sigstore, and verification checks both the subject
digest and certificate claims. See GitHub's
[artifact attestation documentation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
for the platform trust model.

## Community evidence contracts

Place agent-only bundles under `submissions/impact/` or policy-effectiveness
bundles under `submissions/control/`, then open a pull request. CI performs
offline recomputation for every bundle and performs online attestation
verification for schema-v2 bundles that claim GitHub provenance. The public
dashboard labels the evidence tier; it never renders a checksum as an identity
claim. Valid control evidence does not need a favorable score.

Before submitting:

```bash
dspy-security-bench proofrun verify submissions/impact/your-agent.json
dspy-security-bench proofrun verify submissions/control/your-agent-policy.json
```

Use only synthetic inputs. Never include customer records, private prompts,
credentials, production tool outputs, or restricted acquisition information.
