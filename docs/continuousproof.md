# ContinuousProof

ContinuousProof compares verified assurance evidence after a model, adapter,
policy, protocol, tool, or data-source change.

```bash
dspy-security-bench watch baseline report.json --label approved-v1 --out baseline.json
dspy-security-bench watch compare baseline.json candidate.json \
  --max-regression 0.02 --out drift.json
dspy-security-bench watch verify drift.json
```

A snapshot contains the source evidence digest, comparable identity fields,
numeric metrics, and its own canonical digest. A drift report records identity
changes, all common metric deltas, directionality, the owner-supplied threshold,
and whether review is needed.

On main, comparison requires the same **nonempty metric keys** on both sides.
Removed, added, or entirely missing metrics are not silently dropped; the CLI
exits 2 and requires a separate review of the changed measurement surface.
Thresholds must be finite, nonnegative numbers. Preserve historical reports:
older reports that relied on silently intersecting different metric sets no
longer verify under the corrected comparison rules.

Snapshot verification alone establishes self-consistency, not source derivation
or authenticated execution. To re-run native verification and reconstruct the
snapshot from its retained source:

```bash
dspy-security-bench watch verify baseline.json --evidence report.json
```

This rejects a self-rehashed snapshot with edited metrics or identity. The
`--evidence` option is for snapshots; verify each embedded snapshot against its
own source before relying on a drift report. Retain sources and independent
digest pins through your review process. Fabricated but internally consistent
source evidence is not authenticated by this operation. The watch CLI now uses
the shared bounded strict JSON reader, including for controller inputs.

Supported source reports are AgentGraphTwin v1/v2, AuthorityTwin,
MissionPackTwin, IncidentTwin, TraceProof analysis, ScheduleProof,
CollectiveGuard v1/v2, DefenderTwin, ResilienceGraph, and ValueProof observations.
The source report is independently verified before a baseline can be created.
Directionality is explicit: higher security/utility rates are better, while
findings, severity counts, unsafe effects, cost, latency, review time, recovery
time, and portability rework are lower-is-better.

DefenderTwin snapshots additionally normalize attack-path closure, weakness
remediation, mission continuity, evidence completeness, trusted-defender gate,
rollback, introduced risk, and declared disruption into comparable numeric
metrics. For example:

```bash
dspy-security-bench watch baseline safe-report.json \
  --label approved-remediation --out safe-baseline.json
dspy-security-bench watch baseline candidate-report.json \
  --label candidate-remediation --out candidate.json
dspy-security-bench watch compare safe-baseline.json candidate.json \
  --max-regression 0 --out remediation-drift.json
```

ResilienceGraph snapshots preserve the campaign digest and normalize candidate
eligibility, feasible/frontier counts, whether a fully scenario-robust portfolio
exists, and the deterministic reference's robust-scenario, worst-case direct-
service, and dependency-reach values. Resource allocation and portfolio
acceptance remain owner decisions.

ContinuousProof is evidence-change detection, not a production observer. It
does not schedule tests, monitor infrastructure, choose thresholds, accept
risk, determine compliance, or approve deployment. CI may use its exit status
to request review, but the accountable owner defines the response.

## Observe-only controller and longitudinal timeline

The controller on main turns owner-selected evidence files into a bounded
observation plan. Freshness, evidence type, digest verification, and regression
thresholds are evaluated offline. The emitted summary always records
`actions_taken: 0`; no workload, credential, policy, network, or deployment
state is changed.

```bash
dspy-security-bench watch controller init \
  --plan-id daily-assurance --evaluation-time 1767225600 \
  --job-id collectiveguard --evidence-ref collective-report.json \
  --kind collective-v2 --last-updated-at 1767225500 --max-age 3600 \
  --out observation-plan.json

dspy-security-bench watch controller observe observation-plan.json \
  --evidence-root artifacts --out observation.json

dspy-security-bench watch controller append observation.json \
  --timeline-id production-assurance --out assurance-timeline.json
dspy-security-bench watch controller verify assurance-timeline.json
```

To append again, pass the existing timeline with `--timeline`. Each entry binds
the full observation, its digest, the prior entry digest, a contiguous sequence,
and a strictly increasing owner-supplied evaluation time. Duplicate observations
are rejected. This establishes local tamper evidence;
it does not authenticate the author or replace external signature trust.

On main, stored observations are also checked against their embedded plan and
snapshots: job identity, freshness, reasons, status, comparison results, and
summary counts must recompute. A rehashed favorable summary cannot hide a stale
job or a regression. Timeline timestamps must equal the embedded observation's
evaluation time; future-dated evidence timestamps are rejected at planning.
Controller-owned invalid-input diagnostics retain the exception class, not its
potentially private message. Direct dependency logging is outside that boundary.

Envelope verification and timeline checking still cannot authenticate the source
or prove that a declared failure occurred. Use controller `verify` with retained
evidence when available, and preserve independently pinned artifacts. Existing
invalid-input observations may need a newly generated source-backed observation
because diagnostic text is now deliberately withheld; keep historical originals.
