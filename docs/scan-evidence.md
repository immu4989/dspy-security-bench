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

New executions use `complete-binary-observations-v2`. A local suite proxy converts
exceptions escaping task execution or evaluation into a distinct execution error
before AgentDojo's selected provider-error fallbacks can turn them into binary
scores. No completed gate or evidence file is emitted for that incomplete scan.
This covers scored pairs and auxiliary task runs. Exceptions suppressed inside
an agent/SDK/evaluator remain unobservable here; deliberate AgentDojo abort
handling retains its environment-based evaluation. Existing raw provider/trace
logging is outside the content-minimal export guarantee.

V1 evidence remains replayable under its original scope. Matched comparison and
scope-bound baseline checks reject mixed measurement protocols. The generic and
DSPy runners require fresh execution rather than trusting legacy AgentDojo cache
entries whose error state is not verified. This is not a finding that any specific
published historical model score contained such errors; that requires its retained
run evidence and original revision.

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

## Compare an upgrade case by case

Capture before/after scans under the same task scope, dependency version, and
stable `agent.name`. Then compare their evidence without more model calls:

```bash
dspy-security-bench scan compare before-evidence.json after-evidence.json \
  --json upgrade-comparison.json --html upgrade-review.html --fail-on-regression

dspy-security-bench scan compare before-evidence.json after-evidence.json \
  --verify upgrade-comparison.json --fail-on-regression
```

The comparator verifies both sources first and requires exactly matched scope
and case identities. It does not silently drop unmatched cases, relabel agents,
or compare a different benchmark version. Both source digests are bound into
the result. Use `--before-sha256` and `--after-sha256` for independently retained
pins. Use a new output filename; existing files are never overwritten.

For **security and task utility separately**, every cell and the total report
record newly failing, newly succeeding, still-successful, and still-failing
cases. Changed-case identities make follow-up review possible without exporting
the prompts. For example, a 50% → 50% aggregate can conceal one newly failing
case and one newly succeeding case. The new success does not erase the new
failure. Likewise, improved injection resistance does not hide lost utility.

`--fail-on-regression` exits 1 if either owner-selected allowance is exceeded:
`--max-new-security-failures` and `--max-new-utility-failures` both default to 0.
Without that flag, a valid comparison exits 0; invalid evidence or scope exits 2.
Failed comparisons are still saved for review. When verifying a saved report,
supply the same explicit allowances; its embedded policy is not allowed to
silently override the CLI's choices.

`comparison_requirements_met` only means the new-failure allowances were met.
Two unchanged, failing scans can meet a no-new-failures comparison. The
`source_review` block preserves each scan's own requirement outcome and flags
source gate-policy or baseline changes. Those flags require separate owner
review; the new-failure gate does not approve or block those changes itself.

This is descriptive pairing, **not a significance test, causal attribution,
ranking, or model-upgrade approval**. A single stochastic run may change. Cases
can share users, tools, or attack logic, so they are not assumed independent.
Retain trial-level evidence and use a predeclared repeated study when you need
stronger inference. The
[comparison schema](../dspy_security_bench/schemas/scan-comparison.schema.json)
supports structural intake; exact verification still needs both source files.

Open `upgrade-review.html` for an offline, keyboard-accessible review with
security/utility counts, new-failure allowances, original scan outcomes, changed
case identities, and retained source digests. It loads no scripts, remote assets,
fonts, or analytics. Both the screen and print view show at most 50 changed cases,
with the omission count labeled; retain the complete comparison JSON and sources.
The HTML is a presentation, not a standalone verifier or signed approval. The CLI
recomputes source evidence before rendering. JSON and HTML outputs require new,
distinct files; an unexpected filesystem I/O failure may still leave one output
without the other, so retain successful command status with your review.
