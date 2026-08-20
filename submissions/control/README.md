# Open Control Evidence submissions

This directory is the public registry for repeated policy-off/policy-on
experiments. Each entry contains the policy document and digest, every raw
ControlTwin child report, paired uncertainty, agent and policy source links,
and a canonical bundle digest. CI recomputes the complete evidence tree without
calling a model.

The registry accepts valid evidence even when a control performs poorly. That
is intentional: it exists to make residual harm and utility tradeoffs visible,
not to collect only flattering scores. Public comparison requires at least five
trials, fresh agents for every case and condition, zero runtime errors, and
redacted tool arguments.

## Submit control evidence

The trusted builder is the recommended path:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write

jobs:
  control-evidence:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.14.0
    with:
      evidence-kind: control
      agent: your_package.security:build_agent
      policy: policies/production.yaml
      trials: 10
      min-containment-lower-bound: 0.70
```

You can also create a local, self-attested bundle:

```bash
dspy-security-bench proofrun control \
  --agent your_package.security:build_agent \
  --policy policies/production.yaml \
  --policy-source "https://github.com/you/agent/blob/COMMIT/policies/production.yaml" \
  --trials 10 \
  --submitter "@your-github-handle" \
  --agent-source "https://github.com/you/agent/tree/COMMIT" \
  --out submissions/control/your-agent-policy.json \
  --card-out control-evidence.svg

dspy-security-bench proofrun verify \
  submissions/control/your-agent-policy.json --offline
```

Do not edit generated JSON by hand. Use a lowercase kebab-case filename and
open a pull request containing the bundle. An attestation badge appears only
after reviewers verify the signature for the exact digest and record it in
`submissions/attestations.json`.

## Scope

Registry entries are repeated evidence for five fixed synthetic ProcureBench
pairs. They are not certifications, population estimates, predicted losses, or
independent observation of a hosted model provider.
