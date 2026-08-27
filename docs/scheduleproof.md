# ScheduleProof

ScheduleProof is a bounded, deterministic model checker for authorization races
in tool-using and multi-agent systems. Give it a data-only event graph and it
enumerates every reachable topological schedule up to a declared ceiling,
checks eight execution-boundary invariants, and returns the shortest observed
unsafe prefix with its causal events and a concrete repair direction.

It executes no model, tool, policy backend, credential, or production action.
It is useful before integration tests and beside runtime traces; it is not a
replacement for either.

## The gap it closes

A fixed temporal test can show that one chosen ordering is unsafe. It cannot
show whether another ordering allowed by the same implementation is also
reachable. This matters when an approval, resource-bound token exchange,
revocation, and external effect can run concurrently:

```text
approval ───────────────┐
grant ─→ token exchange ├─→ effect commit
                       └─→ revocation
```

If commit and revocation are unordered, a happy-path test can pass while a
valid alternate schedule consumes stale authority. ScheduleProof makes the
partial-order assumption explicit and searches its bounded schedule space.

## Quick start

```bash
pip install dspy-security-bench

# Compare one bounded and three intentionally racy synthetic profiles.
dspy-security-bench schedule demo

# Start from a strict data-only scenario; no application code is imported.
dspy-security-bench schedule init \
  --profile revocation-race --out scheduleproof.json

dspy-security-bench schedule run scheduleproof.json \
  --json-out artifacts/scheduleproof.json \
  --sarif-out artifacts/scheduleproof.sarif \
  --fail-on-unsafe --require-complete

# Recompute every count, class, causal slice, and digest offline.
dspy-security-bench schedule verify artifacts/scheduleproof.json
```

Available starter profiles are `hardened-payment`, `revocation-race`,
`token-race`, and `approval-replay`. They use fictional identifiers and effects.
They are scorer and authoring fixtures, not results for a product or agency.

## Scenario contract

A scenario declares:

- two to twelve typed events: `grant`, `revoke`, `approval`,
  `token_exchange`, and `effect`;
- the directed `happens_before` edges an implementation actually guarantees;
- the invariant set to check; and
- an exploration ceiling from 1 through 100,000 schedules.

CLI inputs are bounded to 1 MiB, event and identifier fields are length-bounded,
and a graph can contain at most the 66 distinct edges possible across twelve
events. These are denial-of-service and reviewability controls, not scale claims.

The scenario schema is packaged at
[`scheduleproof-scenario.schema.json`](../dspy_security_bench/schemas/scheduleproof-scenario.schema.json).
Unknown fields, duplicate IDs or edges, cycles, unbounded strings, unsupported
event kinds, and noncanonical JSON values fail closed.

Do not add an edge because it is desired or appears in a diagram. Add it only
when the deployed design enforces that order—for example with a transaction,
compare-and-set, queue dependency, synchronous response, or commit-time policy
check. Otherwise the evidence silently describes a stronger system than the
one being evaluated.

## Frozen v1 invariants

| Invariant | Question at the execution boundary |
|---|---|
| `active_authority_at_use` | Was the named authority granted and not revoked at exchange and commit? |
| `approval_before_effect` | Did a matching decision exist before the effect? |
| `single_use_approval` | Was the decision consumed no more than its declared maximum? |
| `token_before_effect` | Was the resource-bound token exchanged before use? |
| `scope_attenuation` | Did every token and effect remain within the granted scopes? |
| `audience_binding` | Did the canonical target audience remain unchanged? |
| `identity_binding` | Did subject and resource remain bound across hops? |
| `unique_effect_and_receipt` | Were effect and receipt IDs protected from replay? |

The protocol payload, algorithm, bounds, invariant text, claim boundary, and
outcome vocabulary have a canonical SHA-256 identity. Custom scenarios receive
a separate scenario digest, so changing a dependency cannot be presented as
the same experiment.

## Reading a report

`reachable_schedule_count` is the exact number of topological orderings of the
declared graph. `complete_exploration` is true only when the analyzer visited
all of them. Status has three possible values:

- `bounded_safe`: the search was complete and no declared invariant failed;
- `unsafe`: at least one explored schedule failed; or
- `incomplete_review`: the exploration ceiling was reached without an observed
  failure, so bounded safety is not claimed.

`unsafe_schedule_fraction` is the ratio within the explored schedule space.
The report permanently records
`unsafe_schedule_fraction_is_probability: false`; the ratio is not a frequency
estimate for production, because no runtime scheduler distribution was sampled.

Each failure class retains its minimal lexicographic counterexample, causal
event slice, any mechanically identifiable missing happens-before edge, and a
repair hint. Revocation races normally require atomic commit-time authority
revalidation—not an invented ordering edge.

## CI and longitudinal evidence

`--fail-on-unsafe` returns exit code 1 when an unsafe schedule was found, and
`--require-complete` also fails a truncated exploration. Invalid input and
execution errors return 2. A truncated search with no finding remains
`incomplete_review`; CI should normally use both gates.

SARIF 2.1.0 emits one result per counterexample class for GitHub code scanning.
ContinuousProof accepts verified ScheduleProof reports, binds baselines to both
protocol and scenario digests, and treats unsafe-schedule metrics as
lower-is-better:

```bash
dspy-security-bench watch baseline artifacts/scheduleproof.json \
  --label approved-event-graph --out artifacts/schedule-baseline.json
```

A minimal pull-request job can gate an organization-owned scenario while
retaining the report as evidence:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install dspy-security-bench
- run: >-
    dspy-security-bench schedule run assurance/scheduleproof.json
    --json-out artifacts/scheduleproof.json
    --sarif-out artifacts/scheduleproof.sarif
    --fail-on-unsafe --require-complete
```

Pin third-party actions to reviewed commit SHAs in a production workflow. An
unsafe exit is a technical gate signal; accountable owners still decide how the
finding affects deployment.

## Public-sector and economic use cases

ScheduleProof can make concurrency assumptions reviewable for:

- benefit, grant, payment, and records workflows where human approval must be
  consumed once before an external effect;
- cyber-response systems where containment authority can be revoked while
  parallel agents are still acting;
- acquisition and accounts-payable agents that exchange audience-bound tokens
  before committing a transaction;
- healthcare, financial, and critical-infrastructure assistants that must
  revalidate identity, resource, and scope at the final action boundary; and
- MCP task servers that bind long-running task state and results to an
  authorization context.

These examples describe evaluation opportunities, not agency endorsement,
regulatory coverage, or suitability for a particular deployment.

## Research basis and positioning

The design responds to current primary-source needs:

- the [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  prioritizes secure agent identity, authorization, evaluation, and multi-agent
  interaction;
- the [NCCoE agent identity and authorization concept paper](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept)
  asks for practical identification, authorization, auditing, and
  non-repudiation patterns;
- [NIST's agent evaluation probes](https://www.nist.gov/programs-projects/building-evaluation-probes-agentic-ai)
  emphasize extensible verifiers and machine-readable audit trails;
- the draft [NIST TEVV-Athlon framework](https://www.nist.gov/artificial-intelligence/ai-research/tevv-athlon-framework-evaluating-ai-systems)
  frames evaluation as adaptable TEVV rather than one universal score; and
- stable [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  requires resource targeting and supports least-privilege, audience-bound
  access, while [MCP Tasks](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks)
  requires task-to-authorization-context binding when context is supplied.

This project does not claim that topological sorting, model checking,
authorization invariants, or race testing is individually new, and it does not
claim a global first. The contribution is an open, strict, content-addressed
agent-authorization schedule protocol with exact bounded coverage, minimal
causal counterexamples, SARIF, longitudinal evidence, and offline semantic
recomputation in one operator-owned workflow.

## Threats to validity and explicit non-claims

- The analyzer checks the graph supplied by the operator; it cannot discover
  omitted services, events, queues, retries, clocks, failures, or telemetry.
- Events are atomic in v1. Network partitions, weak memory, clock drift,
  Byzantine behavior, and probabilistic scheduling are out of model.
- Twelve events and 100,000 explored schedules are deliberate reviewability
  and denial-of-service bounds, not a claim of enterprise-scale verification.
- A complete bounded result does not establish production reachability or
  production safety. An incomplete result cannot be called safe.
- Repair hints are engineering leads. Owners must validate implementations,
  residual risk, accessibility, privacy, records, legal, and mission impacts.
- Nothing here is certification, compliance, source selection, risk acceptance,
  government endorsement, or an authorization to operate.
