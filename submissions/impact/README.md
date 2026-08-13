# ProofRun community submissions

This directory accepts independently inspectable ProofRun/RepeatTwin bundles.
Contributors run their own agent, preserve every raw trial, create a
content-addressed bundle, and open a pull request. CI recomputes all published
statistics and rejects modified or underpowered bundles without making a model
call. Eligible bundles must also record a fresh agent instance for every case,
which the CLI does automatically from the supplied zero-argument factory.

## Submit a result

```bash
# 1. Run and package at least five complete trials. Ten is recommended.
dspy-security-bench proofrun run \
  --agent your_package.security:build_agent \
  --trials 10 \
  --submitter "@your-github-handle" \
  --agent-source "https://github.com/you/your-agent" \
  --out submissions/impact/your-agent.json

# 2. Recompute the bundle before opening a pull request.
dspy-security-bench proofrun verify submissions/impact/your-agent.json --offline
```

For GitHub/Sigstore provenance and the stronger trusted-builder tier, use the
versioned reusable workflow documented in [`docs/proofrun.md`](../../docs/proofrun.md).
The dashboard only awards a cryptographic tier after the bundle digest is
recorded in the separately reviewed `submissions/attestations.json` registry.

Do not edit generated JSON by hand: its canonical SHA-256 digest covers the
entire report. Use a filename containing only lowercase letters, digits, and
hyphens.

## What “verified” means

Offline verification confirms that the protocol identity, raw trials,
statistics, Wilson intervals, usage totals, and content hashes agree. ProofRun
may additionally bind the exact bytes to a GitHub workflow, source commit, and
hosted runner. That provenance is not independent observation of a remote model
provider. Results remain scoped to five frozen synthetic ProcureBench pairs and
are not safety or compliance certifications.
