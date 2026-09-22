# Recompute a scan without repeating model calls

**On main; not yet in the published v0.19.0 package.** Use this workflow when a
reviewer needs to check how a scan verdict was derived without accessing provider
credentials or paying to run the model again.

## Capture and verify

After reviewing the scan plan and authorizing its model/tool use:

```bash
dspy-security-bench scan --config .dspy-security-bench.yaml \
  --evidence-json scan-evidence.json --json scan-report.json

dspy-security-bench scan verify scan-evidence.json
dspy-security-bench scan verify scan-evidence.json --fail-on-shortfalls
```

Evidence export requires a new file, bounded by 50 MB and 100,000 scored cases.
It cannot be combined with plan-only or write-baseline modes. Output collisions
and incompatible modes are rejected before constructing the agent. A completed
scan that fails its gate still writes evidence; an incomplete execution does not
produce a complete evidence artifact. Auxiliary injection-task utility runs are
not scored case observations and are not included.

`scan verify` exits **0 for valid recomputation**, even when the saved requirements
were not met; it exits **2 for invalid/unreadable evidence**. Add
`--fail-on-shortfalls` to exit **1 for valid evidence with unmet requirements**,
regardless of the scan's original non-blocking enforcement choice. Verification
never constructs an agent, resolves a provider, or invokes a model.

## What is retained?

- Frozen declared scope: suite/task/attack/defense identities, stable agent label,
  measurement protocol, and reported AgentDojo distribution version.
- Minimal case rows: those identities plus binary utility, security, and
  injection-success outcomes. Unknown row fields are not exported.
- Gate thresholds, sample minimum, uncertainty setting, and enforcement policy.
- The baseline snapshot loaded before execution, if this is a regression scan.
  The local baseline filename is not retained.
- The recomputed report, explicit limitations, and canonical evidence digest.

No prompts, responses, tool results, raw logs, provider credentials, model API
configuration, or agent import path is exported as a dedicated field. The default
agent label may nevertheless equal a model/import name; choose an appropriate
stable `agent.name` and review all identifiers before sharing. This is field
minimization, **not** an anonymizer or a secret scanner. Baseline labels and owner
identifiers can also be sensitive.

## What verification establishes—and what it does not

The verifier requires exactly one row per declared matrix position; rejects
duplicates, substitutions, missing outcomes, hidden fields, and inconsistent
binary outcomes; recomputes aggregates and uncertainty bounds; rechecks the
baseline and scope; and reconstructs the report. Rehashing an edited score or
verdict does not make it pass. The shipped
[JSON Schema](../dspy_security_bench/schemas/scan-evidence.schema.json) is only a
structural intake aid, not a substitute for these semantic checks.

The declared matrix is not independently resolved against an installed benchmark
registry, and the recorded distribution version is not a source-code digest.
Retain the benchmark revision, dependency lockfile, approved input sources, and
execution provenance separately. Upstream runtime errors already encoded as
binary outcomes cannot be recovered as separate errors by this format.

Anyone can fabricate a new, internally consistent observation set. Therefore
successful replay is **not authenticated execution**, proof that observations
are true, a signature verification, or a safety certification. If an owner has
independently retained an expected digest, require it:

```bash
dspy-security-bench scan verify scan-evidence.json \
  --expected-sha256 "$REVIEWED_EVIDENCE_SHA256" --fail-on-shortfalls
```

The pin is the `evidence_sha256` printed by the original reviewed capture, not
the SHA-256 of prettified file bytes. Obtain it through your independent review
or provenance process. Reading a digest from the same untrusted file does not
authenticate it. The command does not fetch keys, sign files, contact a service,
or upload anything.

Keep historical evidence and the revision that produced it. Exact replay is tied
to the `scan-evidence-v1` output contract; changes to that contract require a new
protocol version rather than silently rewriting archived evidence.
