# AssuranceGraph: executable claim–evidence cases for AI agents

AssuranceGraph answers a narrow but operationally important question:

> Which deployment claims are supported, violated, contradicted, stale, or
> missing under one declared system boundary and evaluation time?

It composes existing DSPy Security Bench reports without turning them into a
universal score. Every referenced artifact is first recomputed by its native
offline verifier. Frozen profile predicates are then applied to scalar summary
fields, and the result is bound to the case, profile, protocol, evidence
digests, owners, observation times, and report digest.

AssuranceGraph does not deploy, stop, restart, approve, certify, procure, or
accept risk for a system.

## Five-minute complete demo

```bash
git clone https://github.com/immu4989/dspy-security-bench.git
cd dspy-security-bench
uv sync --locked --extra dev

uv run dspy-security-bench assure demo --out-dir artifacts/assurancegraph

uv run dspy-security-bench assure verify \
  artifacts/assurancegraph/assurance-report.json \
  --evidence-root artifacts/assurancegraph
```

AssuranceGraph is currently available from `main` and will enter the PyPI
package in the next release.

The fictional critical-infrastructure demo produces:

```text
artifacts/assurancegraph/
├── assurance-case.json
├── assurance-report.json
├── assurance.sarif
├── assessment-results.json
├── index.html
└── evidence/
    ├── authority.json
    ├── trace.json
    ├── collective-v2.json
    ├── schedule.json
    ├── verified-defense.json
    ├── defense-portfolio.json
    ├── containment.json
    └── dependency-impact.json
```

Every artifact is synthetic. The HTML file is a standalone executive and
engineering report; it makes no network request and contains no source evidence
payloads.

## Build an organization-owned case

Choose the closest engineering default:

```bash
dspy-security-bench assure profiles
dspy-security-bench assure profiles federal-high-impact
dspy-security-bench assure sectors
dspy-security-bench assure sectors public-benefits

dspy-security-bench assure init \
  --profile federal-high-impact \
  --case-id benefits-assistant-pilot \
  --out assurance-case.json

# Or start with an explicit fictional sector boundary.
dspy-security-bench assure init --sector public-benefits \
  --case-id benefits-assistant-pilot --out assurance-case.json
```

Before evaluation, replace:

- the fictional system, mission, environment, and boundary;
- the accountable decision and evidence owners;
- `evaluation_time` and every `observed_at` timestamp;
- each local evidence path;
- each `expected_sha256` with the canonical JSON digest of the reviewed evidence; and
- profile defaults that are unsuitable for the decision by proposing a new,
  reviewed profile rather than silently changing a frozen one.

Compute a pin only after native verification succeeds:

```bash
dspy-security-bench assure digest evidence/authority.json
dspy-security-bench assure digest evidence/authority.json --json
```

The starter uses an all-zero digest as an unmistakable placeholder. Raw
`sha256sum` output is not interchangeable because AssuranceGraph hashes
canonical JSON content so insignificant formatting changes do not change its
identity.

Evaluate and export review surfaces:

```bash
dspy-security-bench assure evaluate assurance-case.json \
  --evidence-root . \
  --out assurance-report.json \
  --sarif-out assurance.sarif \
  --oscal-out assessment-results.json \
  --html-out assurance.html \
  --fail-on-review
```

`--fail-on-review` returns nonzero unless every claim is supported. The report
is written first, so CI preserves the evidence even when the gate fails.

Export and recompute a closed federal review pack:

```bash
dspy-security-bench assure federal-pack assurance-report.json \
  --evidence-root . --out-dir federal-review
dspy-security-bench assure federal-verify federal-review --evidence-root .
dspy-security-bench assure exchange-verify
```

The pack records zero automatic control determinations, risk acceptances, and
authorizations to operate. See the [Assurance Control Plane](assurance-control-plane.md)
for ContainmentProof, AgentBOM, sector starters, probe conformance, and public
reproduction semantics.

## Claim semantics

| Status | Exact meaning |
|---|---|
| `supported` | At least one current, natively verified artifact satisfies every frozen predicate and no current artifact violates it. |
| `violated` | Current, natively verified evidence fails one or more predicates. |
| `contradicted` | Current verified evidence both supports and violates the same claim. |
| `stale_evidence` | Only otherwise usable evidence older than its declared maximum age is present. |
| `missing_evidence` | No current verified artifact can evaluate the claim, including missing, invalid, wrong-kind, future-dated, or digest-mismatched evidence. |

Contradiction is never resolved by selecting the favorable artifact. A valid
digest proves content identity, not that external observations are true. A
supported result means only that the supplied evidence satisfies one profile
inside the declared boundary.

## Built-in profiles

| Profile | Required evidence |
|---|---|
| `enterprise-agent` | AuthorityTwin, TraceProof, DefenderTwin, ContainmentProof, AgentBOM ClaimImpact |
| `frontier-lab` | AuthorityTwin, TraceProof, CollectiveGuard v2, ScheduleProof, DefenderTwin, ContainmentProof, AgentBOM ClaimImpact |
| `federal-high-impact` | AuthorityTwin, TraceProof, CollectiveGuard v2, ScheduleProof, DefenderTwin, ContainmentProof, AgentBOM ClaimImpact |
| `critical-infrastructure` | All above plus ResilienceGraph |

The similarly shaped frontier and federal profiles are intentionally separate:
their owner context, review process, evidence retention, control selection, and
legal authority differ even when this first protocol asks the same technical
questions.

Mappings to NIST publications, OMB memoranda, control families, and telemetry
standards are `informative-not-determinative`. OSCAL output contains technical
observations and findings, not control satisfaction. An agency assessor must
connect them to an authorized Assessment Plan and actual system boundary.

## Native verification before composition

AssuranceGraph currently accepts these verified report kinds:

- `authority` — AuthorityTwin;
- `trace` — TraceProof;
- `collective-v2` — provenance-aware CollectiveGuard;
- `schedule` — ScheduleProof;
- `verified-defense` — DefenderTwin; and
- `defense-portfolio` — ResilienceGraph;
- `containment` — ContainmentProof harmless canary controls; and
- `dependency-impact` — AgentBOM dependency-to-claim impact analysis.

It does not accept arbitrary JSON assertions. Adding an evidence kind requires
a deterministic semantic verifier, stable identity, bounded input, explicit
claim boundary, tests for unfavorable outcomes, and reviewed profile predicates.

Evidence paths must be relative and resolve beneath `--evidence-root`. Files
are bounded to 50 MB, cases to 1 MB, and each case to 100 evidence references.
No expression language, Python hook, URL fetch, model call, credential, prompt,
or production action is supported.

## Why this helps organizations

- **Engineering teams** get one CI gate and a trace from each claim to exact
  canonical evidence content.
- **Security teams** see unfavorable and contradictory reports instead of a
  selectively favorable dashboard.
- **Executives and mission owners** get a readable, scope-bound HTML case
  without losing the underlying engineering detail.
- **Federal assessors** get non-certifying OSCAL observations with explicit
  ownership and boundary language.
- **Vendors and technology partners** can publish native evidence without
  granting the repository authority to rank or approve their products.
- **Researchers** get a falsifiable composition protocol whose conclusions can
  be recomputed from the same artifacts.

This direction aligns with NIST's [AI Agent Standards
Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
and its work on [machine-readable evaluation
probes](https://www.nist.gov/programs-projects/building-evaluation-probes-agentic-ai).
It also supports the performance, interoperability, and review needs described
in [OMB M-25-22](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf)
without claiming that an open-source report fulfills those requirements.

## Explicit non-claims

AssuranceGraph does not establish:

- production safety, security, reliability, alignment, or legal compliance;
- the completeness or truth of external telemetry;
- that a bounded model matches a real distributed system;
- that a synthetic remediation will work in production;
- that a profile is an agency control baseline;
- that supported claims justify deployment; or
- that missing evidence proves a system is unsafe.

ContainmentProof and AgentBOM ClaimImpact now add harmless canary evidence and
exact dependency-to-claim change analysis without exposing live targets,
loading third-party code, or taking operational action.
