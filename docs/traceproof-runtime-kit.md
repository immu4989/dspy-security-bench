# TraceProof Runtime Kit

The Runtime Kit instruments the existing `Agent` / `BenchTool` execution
boundary and emits content-free OTLP JSON that TraceProof can sanitize and
recompute offline. It is designed for teams that need evidence about
authorization continuity and consequential effects without putting prompts,
responses, arguments, tool results, or provider credentials into a trace.

This is especially useful when a public agency or regulated company must keep
operational content in an approved boundary while giving engineers,
assessors, and system owners a common, reviewable evidence format. It supports
the measurement and interoperability direction of the
[NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
without claiming NIST approval, compliance, or an authorization to operate.

## 1. Inspect without executing

```bash
dspy-security-bench trace runtime list
dspy-security-bench trace runtime doctor --root . --framework langchain
```

The doctor reads dependency manifests only. It does not import the target,
load credentials, start an agent, call a model, or invoke a tool. Presets cover
OpenAI Agents SDK, LangChain/LangGraph, Pydantic AI, CrewAI, AutoGen, DSPy, MCP,
and a custom callable loop through the same framework-neutral boundary.

## 2. Generate the boundary

```bash
dspy-security-bench trace init-policy --out traceproof-redaction.yaml
dspy-security-bench trace runtime scaffold \
  --agent myapp.agent:build_agent \
  --out traceproof_target.py \
  --trace-out artifacts/traceproof-otlp.json
```

Review the generated `security_context` function. It can inspect tool arguments
locally to query your policy or authorization layer, but its return value is
restricted to bounded `dsb.auth.*`, `dsb.approval.*`, `dsb.delegation.*`,
`dsb.effect.*`, and `dsb.mcp.*` metadata. The recorder rejects arbitrary
application attributes. An unclassified tool call records an explicit
`unknown` decision rather than inventing an allow.

A direct integration has the same shape:

```python
from dspy_security_bench.trace.runtime import TraceRecordingAgent


def security_context(tool_name, arguments):
    decision = local_authority_check(tool_name, arguments)
    return {
        "dsb.auth.required": True,
        "dsb.auth.decision": "allow" if decision.allow else "deny",
        "dsb.auth.resource": decision.resource,
        "dsb.auth.token_audience": decision.token_audience,
        "dsb.auth.requested_scopes": decision.requested_scopes,
        "dsb.auth.granted_scopes": decision.granted_scopes,
        "dsb.auth.token_passthrough": False,
        "dsb.effect.external": decision.external_effect,
    }


agent = TraceRecordingAgent(
    build_agent(),
    output_path="artifacts/traceproof-otlp.json",
    security_context=security_context,
)
```

Do not derive these values from untrusted model text. Bind them to the
authorization decision, resource, and effect boundary that actually executed.

## 3. Sanitize, analyze, and gate

```bash
dspy-security-bench trace import artifacts/traceproof-otlp.json \
  --policy traceproof-redaction.yaml \
  --out artifacts/trace-evidence.json
dspy-security-bench trace analyze artifacts/trace-evidence.json \
  --out artifacts/trace-report.json \
  --sarif-out artifacts/trace-results.sarif \
  --oscal-out artifacts/trace-assessment-results.json
```

`trace analyze` exits `1` for critical/high findings, `0` otherwise, and `2`
for invalid input. Operators should fail closed if telemetry they require is
missing; absence of a finding is not proof of instrumentation completeness.

## 4. Probe MCP authorization

When the boundary represents MCP over Streamable HTTP, record only the bounded
`dsb.mcp.*` facts and run:

```bash
dspy-security-bench trace mcp analyze artifacts/trace-evidence.json \
  --out artifacts/mcp-authorization-report.json
```

The probe is pinned to MCP 2025-11-25 and checks resource indicators,
canonical resource binding, downstream audience validation, token
passthrough, Protected Resource Metadata discovery, issuer evidence, header
transport, bounded step-up retries, and authorization-error semantics. It
separates coverage from outcome so unobserved requirements remain visible.

## 5. Run the reference lab

The repository includes a one-command, fictional integration using a real OPA
decision service, OTLP/HTTP, and OpenTelemetry Collector file exporter:

```bash
./examples/traceproof-runtime-lab/run.sh
```

The lab pins versioned OPA, Collector, and Python images, runs containers
read-only with `no-new-privileges`, emits no prompts or credentials, and writes
recomputable evidence under `examples/traceproof-runtime-lab/artifacts/`.
Version tags are not immutable image digests; production adopters should pin
approved digests in their own supply-chain process.

## 6. Publish only sanitized evidence

After a human privacy review, create a community bundle:

```bash
dspy-security-bench trace bundle \
  artifacts/trace-evidence.json artifacts/trace-report.json \
  --mcp-report artifacts/mcp-authorization-report.json \
  --submitter @your-team \
  --runtime "your-runtime@version" \
  --source-repository https://github.com/owner/repo/tree/COMMIT \
  --out your-runtime.json
dspy-security-bench trace verify-submission your-runtime.json
```

The [open registry](../submissions/trace/README.md) accepts valid negative
results and rejects maintainer demos/reference fixtures. Initial provenance is
self-attested and displayed as such.

## Evidence boundaries

The kit can establish what the supplied, sanitized bytes declare and whether
the deterministic rules recompute. It cannot establish trace completeness,
identity truth, absence of hidden execution paths, model safety, privacy
compliance, system certification, government endorsement, or authorization to
operate. Keep raw telemetry out of issues and pull requests.

The attribute names are project-owned, not official OpenTelemetry semantic
conventions. TraceProof follows the direction of
[OpenTelemetry GenAI observability](https://opentelemetry.io/blog/2026/genai-observability/)
while keeping its security assertions under an explicit `dsb.*` contract.
