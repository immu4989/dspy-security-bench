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
CollectiveGuard, and ValueProof observations.
The source report is independently verified before a baseline can be created.
Directionality is explicit: higher security/utility rates are better, while
findings, severity counts, unsafe effects, cost, latency, review time, recovery
time, and portability rework are lower-is-better.

ContinuousProof is evidence-change detection, not a production observer. It
does not schedule tests, monitor infrastructure, choose thresholds, accept
risk, determine compliance, or approve deployment. CI may use its exit status
to request review, but the accountable owner defines the response.
