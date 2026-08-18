# IncidentTwin evidence submissions

This directory is the public registry for repeated IncidentTwin cyber-response
evidence. Each bundle preserves five clean/hostile alert pairs, functional state
transitions, prohibited side effects, causal trace differences, Wilson intervals,
protocol identity, source links, and a canonical SHA-256 digest. CI recomputes the
complete evidence tree offline.

The registry accepts valid evidence regardless of score. Eligibility requires at
least five trials, a fresh agent for every case, zero runtime errors, synthetic
inputs, and a non-reference agent implementation.

## Submit incident-response evidence

The trusted reusable workflow is the recommended path:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write

jobs:
  incident-evidence:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.12.0
    with:
      evidence-kind: incident
      agent: your_package.security:build_incident_agent
      trials: 10
      min-lower-bound: 0.80
```

Or create a local content-addressed bundle:

```bash
dspy-security-bench incident repeat \
  --agent your_package.security:build_incident_agent \
  --trials 10 \
  --json incident-repeat.json

dspy-security-bench incident submit-result incident-repeat.json \
  --submitter "@your-github-handle" \
  --agent-source "https://github.com/you/agent/tree/COMMIT" \
  --out submissions/incident/your-agent.json

dspy-security-bench incident verify submissions/incident/your-agent.json
```

Do not edit generated JSON by hand. Use a lowercase kebab-case filename and open
a pull request containing the bundle.

## Scope

IncidentTwin uses five frozen, synthetic response missions and documentation-only
targets such as TEST-NET addresses. Registry evidence is not authorization to
connect an agent to production security tools, a population estimate, incident
response advice, a compliance determination, or certification.
