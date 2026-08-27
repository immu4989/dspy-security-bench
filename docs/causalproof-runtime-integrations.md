# CausalProof runtime integrations

CausalProof includes native, zero-provider-call bridges for the **OpenAI Agents
SDK** and **LangGraph**. Each bridge emits two local artifacts:

1. a structural OTLP projection containing only pseudonymized trace/span IDs,
   parent IDs, and timestamps; and
2. an operator-owned manifest binding selected runtime spans to ScheduleProof's
   atomic authorization events.

The bridges do not infer security meaning from span names or application data.
The operator supplies each `grant`, `approval`, `token_exchange`, `revoke`, or
`effect` event and remains accountable for that binding.

```bash
pip install "dspy-security-bench[openai-agents,langchain]==0.18.0"
dspy-security-bench causal integrations

dspy-security-bench causal scaffold openai-agents --out causal_openai.py
dspy-security-bench causal scaffold langgraph --out causal_langgraph.py
```

Generated files are review-first starters. Existing files are never replaced
unless `--force` is passed.

## Shared session contract

Both bridges use `CausalRuntimeSession`. Native runtime identifiers are
deterministically pseudonymized into W3C-sized hexadecimal identifiers before
they enter the local artifacts.

```python
from dspy_security_bench.causal.runtime import CausalRuntimeSession

session = CausalRuntimeSession(
    scenario_id="benefits-record-change",
    title="Fictional benefits record authorization",
    description="Synthetic fixture; no claimant or production data.",
    invariants=[
        "active_authority_at_use",
        "approval_before_effect",
        "token_before_effect",
        "scope_attenuation",
        "audience_binding",
        "identity_binding",
    ],
    asserted_edges=[
        {
            "before": "approve",
            "after": "commit",
            "rationale": "The system of record atomically persists approval before commit.",
        }
    ],
)
```

Assertions are never relabeled as observations. Every assertion requires a
bounded rationale and remains visibly `asserted` in the CausalProof report.

## OpenAI Agents SDK

The SDK's public tracing processor receives trace/span lifecycle callbacks.
CausalProof reads only `trace_id`, `span_id`, `parent_id`, `started_at`, and
`ended_at`; it never accesses `span_data`, errors, trace metadata, prompts,
responses, or tool inputs/outputs.

```python
from agents import custom_span, set_trace_processors, trace

from dspy_security_bench.causal.runtime import OpenAIAgentsCausalProcessor

processor = OpenAIAgentsCausalProcessor(
    session,
    trace_path="artifacts/causal-structure.json",
    manifest_path="artifacts/causal-manifest.json",
)

# Replacing the default processor keeps this trace path under local custody.
# Retaining any other processor creates a separate data-handling boundary.
set_trace_processors([processor])

with trace("fictional-benefits-change"):
    with custom_span("authority-boundary", data=None) as span:
        processor.bind_span(
            span,
            {
                "id": "grant",
                "kind": "grant",
                "actor": "identity-service",
                "authority_id": "authority-1042",
                "subject": "benefits-agent",
                "resource": "benefits-record-1042",
                "scopes": ["record:update"],
                "audience": "benefits-mcp",
            },
        )
        # Run the operation represented by this exact atomic boundary.

processor.write()
```

`processor.bind_current(event)` is available when the binding code already runs
inside the intended SDK span. Bind only spans that genuinely represent an
atomic ScheduleProof event. Intermediate SDK task, model, and handoff spans can
remain structural and unbound. If a bound event's immediate parent is unbound,
CausalProof deliberately returns `review_required`; create an exact custom
atomic boundary or document the missing instrumentation instead of silently
compressing ancestry.

The integration follows the SDK's documented
[`TracingProcessor`](https://openai.github.io/openai-agents-python/ref/tracing/)
interface. The Agents SDK may capture sensitive model and function data in its
own span payloads by default; this processor does not read those payloads. Local
custody also requires replacing or separately governing every other configured
trace processor.

## LangGraph

The LangGraph bridge is a `BaseCallbackHandler`. It observes callback lifecycle
IDs and the stable `langgraph_node` metadata key. Graph inputs, outputs, state,
messages, errors, and tool data are discarded without inspection.

```python
from dspy_security_bench.causal.runtime import LangGraphCausalCallback

callback = LangGraphCausalCallback(
    session,
    node_events={
        "authorize": {
            "id": "grant",
            "kind": "grant",
            "actor": "identity-service",
            "authority_id": "authority-1042",
            "subject": "benefits-agent",
            "resource": "benefits-record-1042",
            "scopes": ["record:update"],
            "audience": "benefits-mcp",
        },
        # Bind additional nodes to approval, exchange, revoke, or effect events.
    },
    trace_path="artifacts/causal-structure.json",
    manifest_path="artifacts/causal-manifest.json",
)

graph.invoke(input_state, config={"callbacks": [callback]})
callback.write()
```

LangGraph node runs are usually siblings beneath the graph invocation. Their
callback parent IDs therefore do **not** prove the graph's sequential edges.
Declare compiled graph guarantees as explicit `asserted_edges`; CausalProof
will preserve their asserted provenance. Never convert callback completion
times into causal edges.

For loops or retries, supply an occurrence factory instead of a static event:

```python
def bind_review(node_name: str, occurrence: int):
    return {
        "id": f"review-{occurrence}",
        "kind": "approval",
        # ...operator-reviewed fields...
    }

callback = LangGraphCausalCallback(session, node_events={"review": bind_review})
```

The callback follows LangChain Core's public
[`BaseCallbackHandler`](https://reference.langchain.com/python/langchain-core/callbacks/base/BaseCallbackHandler)
contract and accepts the standard `run_id`/`parent_run_id` lifecycle fields.

## Analyze and publish

```bash
dspy-security-bench causal run \
  artifacts/causal-structure.json artifacts/causal-manifest.json \
  --report-out artifacts/causal-report.json \
  --scenario-out artifacts/schedule-scenario.json \
  --schedule-report-out artifacts/schedule-report.json \
  --fail-on-review --fail-on-unsafe --require-complete
```

Before publishing a community bundle, review the manifest as sensitive
operational metadata. Structural pseudonymization is not anonymization. Record
sampling, dropped spans, uninstrumented services, repeated nodes, and manual
assertions in `--known-gap` entries.

These integrations produce evaluation evidence; they do not prove
instrumentation completeness, deployed-code conformance, incident likelihood,
certification, compliance, government endorsement, risk acceptance, or
authorization to operate.
