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

Supported source reports are AgentGraphTwin v1/v2, AuthorityTwin,
MissionPackTwin, IncidentTwin, TraceProof analysis, ScheduleProof,
CollectiveGuard v1/v2, DefenderTwin, and ValueProof observations.
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
