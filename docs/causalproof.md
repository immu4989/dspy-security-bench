# CausalProof: structural traces to proof-ready authorization schedules

CausalProof converts OpenTelemetry's structural causality into a strict,
provenance-separated ScheduleProof draft. It gives operators a defensible answer
to a hard question: **which ordering constraints did the runtime actually
observe, which ones did the system owner assert, and which apparent orderings
are only clocks?**

The converter is local, deterministic, model-free, content-free, bounded, and
offline-verifiable. It never reads span names, attributes, events, status,
resource data, instrumentation scope, prompts, tool arguments, tool results, or
credentials.

## Why the distinction matters

| Evidence | Meaning | Inserted into ScheduleProof? |
|---|---|---:|
| OTLP `parentSpanId` | observed directional parent within one trace | yes |
| owner assertion | documented architecture guarantee | yes |
| OTLP span link | observed causal relationship without a safe generic direction | no |
| end time ≤ start time | wall-clock review candidate | no |

This is deliberately conservative. The OpenTelemetry Trace API defines one
parent and zero or more causally related links, including links across traces.
It does not make every generic link a directional happens-before edge. The
OpenTelemetry file-exporter specification also says file records are not
guaranteed to be ordered and timestamps are not guaranteed to be monotonic.
CausalProof therefore refuses to turn visual order or wall-clock order into a
proof edge.

Primary specifications:

- [OpenTelemetry Trace API](https://opentelemetry.io/docs/specs/otel/trace/api/)
- [OpenTelemetry OTLP file serialization](https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/)
- [OTLP trace protocol fields](https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)

## Five-minute reference run

```bash
# CausalProof is currently on main and will enter the next tagged release.
pip install "dspy-security-bench @ git+https://github.com/immu4989/dspy-security-bench@main"

dspy-security-bench causal demo --out-dir artifacts/causalproof

# Or create editable fictional inputs.
dspy-security-bench causal init \
  --trace-out causal-trace.json \
  --manifest-out causal-manifest.json

dspy-security-bench causal run causal-trace.json causal-manifest.json \
  --report-out artifacts/causalproof.json \
  --scenario-out artifacts/scheduleproof.json \
  --schedule-report-out artifacts/scheduleproof-report.json \
  --fail-on-review --fail-on-unsafe --require-complete

dspy-security-bench causal verify \
  artifacts/causalproof.json causal-trace.json causal-manifest.json
```

`--fail-on-review` catches missing bound spans, missing or unbound parents and
links, duplicate span identities, dropped OTLP records, and invalid combined
causal graphs. `--fail-on-unsafe` and `--require-complete` pass the generated scenario
through ScheduleProof and enforce the owner's bounded safety gates.

## Binding manifest

OTLP describes execution structure; it does not know that one span means an
authority grant and another means an effect commit. The operator-owned manifest
provides that data-only semantic binding:

```json
{
  "schema_version": 1,
  "manifest_type": "dspy-security-bench-causalproof-manifest",
  "scenario_id": "fictional-benefits-change",
  "title": "Fictional benefits change authorization",
  "description": "Synthetic fixture; no claimant or production data.",
  "bindings": [
    {
      "trace_id": "cccccccccccccccccccccccccccccccc",
      "span_id": "0000000000000001",
      "event": {
        "id": "grant",
        "kind": "grant",
        "actor": "identity-service",
        "authority_id": "authority-1042",
        "subject": "benefits-agent",
        "resource": "benefits-record-1042",
        "scopes": ["record:update"],
        "audience": "benefits-mcp"
      }
    }
  ],
  "asserted_edges": [
    {
      "before": "approve",
      "after": "commit",
      "rationale": "The system of record atomically persists approval before commit."
    }
  ],
  "invariants": ["active_authority_at_use", "approval_before_effect"],
  "exploration": {"max_schedules": 100000}
}
```

The complete JSON Schema accepts all five ScheduleProof atomic event kinds and
rejects extra fields, duplicate bindings, unsafe identifiers, unsupported
invariants, unknown assertion targets, self edges, and cyclic asserted graphs.

## Real-world mission patterns

These are evaluation patterns, not agency requirements or compliance mappings.
Use fictional, synthetic, or appropriately approved metadata.

- **Benefits and case-management changes:** prove that delegated authority,
  case-worker approval, token exchange, revocation, and record mutation remain
  correctly ordered across services.
- **Financial operations and grants:** test whether payment approval,
  segregation of duties, token attenuation, and ledger receipt issuance survive
  retries and parallel execution.
- **Cyber incident response:** reconstruct whether containment authority and
  human approval happened before account isolation, credential rotation, or
  destructive remediation.
- **Supply-chain and procurement workflows:** examine whether a delegated agent
  can commit an order after approval expiry or revocation.
- **Healthcare and regulated data exchange:** test audience, identity, resource,
  and approval binding before an external disclosure without publishing content.
- **Multi-agent enterprise automation:** compare declared orchestration edges
  with observed parents and expose uninstrumented handoffs for review.

The focus matches current public-sector needs without claiming government
adoption. NIST's 2026 [AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
calls for interoperable protocols, agent authentication and identity research,
and state-of-the-art security evaluations. The NCCoE's
[agent identity and authorization concept paper](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
specifically identifies authorization, auditing, non-repudiation, and prompt-
injection controls as open implementation concerns. CausalProof supplies open
measurement infrastructure for those concerns; it is not NIST guidance.

## Public evidence without application content

Build a community bundle after local review:

```bash
dspy-security-bench causal bundle causal-trace.json causal-manifest.json \
  --submitter @you \
  --runtime "your-runtime@version" \
  --source-repository https://github.com/owner/repo/tree/COMMIT \
  --known-gap "head sampling excludes unsampled spans" \
  --out your-runtime.json

dspy-security-bench causal verify-submission your-runtime.json
```

The bundle builder exports only trace/span identifiers, parents, links,
timestamps, and dropped-record counters. It strips all other OTLP fields and
embeds the manifest, CausalProof report, ScheduleProof report, and a canonical
bundle digest. CI recomputes the entire chain for files submitted to
[`submissions/causal/`](../submissions/causal/README.md).

Structural metadata can still be sensitive. Public submission requires owner
review, pinned source provenance, explicit known gaps, and an appropriate
pseudonymization or synthetic-data policy.

## Claim boundary

CausalProof verifies a conversion, not reality outside the supplied bytes. It
cannot prove that every relevant service was instrumented, that sampling kept
every span, that clocks agree, that an assertion matches deployed code, or that
an unsafe schedule is likely in production. ScheduleProof's unsafe fraction is
a bounded schedule-space ratio—not an incident probability.

Results require accountable human review. They are not certifications,
compliance determinations, endorsements, risk acceptances, procurement
decisions, government-authored requirements, or authorizations to operate.
