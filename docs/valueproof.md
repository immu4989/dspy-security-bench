# ValueProof

ValueProof turns owner-supplied, measured mission observations into
content-addressed arithmetic that reviewers can recompute offline. It keeps
security, mission success, cost, latency, human review, recovery effort, and
portability effort in the same bounded record without ranking vendors or
predicting savings.

## Build and verify an observation

```bash
dspy-security-bench value init --out value-observation.json
# Replace every template value with a measured, documented observation.
dspy-security-bench value build value-observation.json \
  --out artifacts/valueproof.json
dspy-security-bench value verify artifacts/valueproof.json
```

The packaged [`examples/value-observation.json`](../examples/value-observation.json)
is synthetic. It demonstrates the schema and is not an economic claim.

ValueProof computes:

- mission-success and safe-mission rates;
- observed cost per attempt, successful mission, and safe mission;
- safe missions per currency unit when cost is non-zero;
- mean latency per attempt;
- human-review minutes per safe mission;
- recovery minutes per attempt; and
- observed portability rework hours.

All inputs remain visible in the proof. A canonical SHA-256 binds the exact
measurement boundary and derived values.

## Compare equivalent observations

```bash
dspy-security-bench value compare \
  artifacts/candidate-a.json artifacts/candidate-b.json \
  --out artifacts/value-comparison.json
```

Comparison is allowed only when `mission_id`, `protocol_sha256`, `currency`,
and the exact accounting `boundary` match. A mismatch produces a
non-comparable artifact and exit code `1`. Even when comparable, ValueProof
emits no rank or recommendation; mission, acquisition, finance, and risk owners
retain the decision.

## Measurement discipline

Use actual observations from an approved experiment or production measurement,
not projections. The `boundary` should identify the model, tools, policy,
infrastructure, time window, included cost categories, human labor treatment,
and excluded costs. The protocol digest should bind the assurance procedure
that produced `safe_missions`.

Do not compare observations with materially different workloads, quality bars,
accounting methods, price bases, or safety protocols merely because the CLI
accepts them. ValueProof checks exact identity fields; it cannot judge whether
two owner-authored boundaries are economically equivalent.

ValueProof is not a forecast, independent cost estimate, cost-benefit analysis,
savings claim, vendor recommendation, source-selection decision, contract
acceptance, audit opinion, or government endorsement.
