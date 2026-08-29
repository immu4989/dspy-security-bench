# Verified Cyber Defense Commons

This directory accepts privacy-bounded DefenderTwin evidence showing whether a
declared remediation closed known attack paths, preserved essential services,
respected target and approval boundaries, introduced no declared risk, retained
rollback, and had complete evidence.

CI recomputes the report and bundle without a model or network connection.
Effective, ineffective, and regression results are useful when their evidence
is complete. Admission validates the frozen data contract; it does not endorse
an adapter, defender, model, vendor, organization, or deployment.

## Submit evidence

```bash
dspy-security-bench defend proposal community-hospital \
  --out proposal.json
dspy-security-bench defend run community-hospital proposal.json \
  --json-out report.json --sarif-out report.sarif.json \
  --oscal-out assessment-results.json
dspy-security-bench defend bundle report.json \
  --submitter @you \
  --runtime "your-defender@version" \
  --source-repository https://github.com/owner/repo/tree/COMMIT \
  --deployment-class synthetic \
  --known-gap "describe adapter, evidence, and test limitations" \
  --out your-defender.json
dspy-security-bench defend verify your-defender.json
```

Use a lowercase kebab-case filename and inspect the exact bytes before opening
a pull request. Public submissions must use fictional or appropriately
sanitized structural evidence and must never include raw telemetry, prompts,
reasoning, credentials, live target identifiers, exploit payloads, or private
unpatched vulnerability details.

For an adapter, start with:

```bash
dspy-security-bench defend adapter init --out adapter-manifest.json
dspy-security-bench defend adapter check adapter-manifest.json
```

Conformance validates a manifest and frozen proposal shape; it does not execute
the adapter or establish production behavior.
