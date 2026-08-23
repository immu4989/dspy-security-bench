# TraceProof

TraceProof is a local, privacy-bounded flight recorder for tool-using AI. It
converts an OpenTelemetry JSON export into pseudonymized evidence, applies
deterministic authorization and effect-integrity rules, and can produce SARIF,
OSCAL 1.2.2 Assessment Results, and a synthetic replay twin.

It never contacts a collector or model provider. Raw prompts, completion text,
tool arguments, credentials, and attributes that the operator did not
explicitly allow are omitted before an evidence artifact is written.

## Try the zero-cost demo

```bash
dspy-security-bench trace demo --out-dir artifacts/traceproof
dspy-security-bench trace verify artifacts/traceproof/trace-evidence.json
dspy-security-bench trace verify artifacts/traceproof/trace-report.json
dspy-security-bench trace verify artifacts/traceproof/trace-twin.json
```

The demo contains fictional telemetry and deliberately triggers five findings.
It does not evaluate a model, product, backend, or deployment.

## Analyze a local OTLP export

```bash
dspy-security-bench trace init-policy --out traceproof-redaction.yaml
# Review the allowlist before processing local data.
dspy-security-bench trace import otlp-export.json \
  --policy traceproof-redaction.yaml \
  --out artifacts/trace-evidence.json
dspy-security-bench trace analyze artifacts/trace-evidence.json \
  --out artifacts/trace-report.json \
  --sarif-out artifacts/trace-results.sarif \
  --oscal-out artifacts/trace-assessment-results.json
dspy-security-bench trace synthesize artifacts/trace-evidence.json \
  --report artifacts/trace-report.json \
  --out artifacts/trace-twin.json
```

`trace analyze` exits `1` when a critical or high finding exists, making it a
usable review gate. It exits `0` when no such finding exists and `2` for an
invalid input or configuration. A finding is deterministic protocol evidence,
not a vulnerability verdict; the accountable owner evaluates context and risk.

## Input contract

TraceProof accepts OTLP JSON with `resourceSpans`, `scopeSpans`, and `spans`, as
produced by common file exporters. Each span may carry standard OpenTelemetry
fields and application-provided `dsb.*` security attributes. Useful attributes
include:

| Attribute | Meaning |
|---|---|
| `dsb.principal_id`, `dsb.agent_id`, `dsb.tenant_id` | authority identities; stored only as keyed hashes |
| `dsb.authenticated` | whether the action had authenticated authority |
| `dsb.requested_audience`, `dsb.granted_audience` | resource-server audience binding |
| `dsb.requested_scopes`, `dsb.granted_scopes` | requested and delegated scopes |
| `dsb.token_passthrough` | bearer token was forwarded through another agent |
| `dsb.approval_required`, `dsb.approval_id`, `dsb.approval_bound` | human-approval evidence |
| `dsb.parent_agent_id`, `dsb.delegated_agent_id` | delegation continuity |
| `dsb.revoked`, `dsb.decision` | revocation state and allow/deny decision |
| `dsb.step_up_required`, `dsb.step_up_completed` | step-up ordering |
| `dsb.effect_expected`, `dsb.effect_receipt_id` | consequential-effect receipt evidence |

The names describe the portable TraceProof contract; they are not an official
OpenTelemetry semantic convention. The project tracks the evolving
[OpenTelemetry GenAI conventions](https://github.com/open-telemetry/semantic-conventions-genai)
and keeps security assertions under the project-owned `dsb.*` namespace.

## Frozen deterministic rules

| Rule | Condition |
|---|---|
| TP001 | action allowed without authenticated authority |
| TP002 | requested and granted audiences differ |
| TP003 | bearer-token passthrough is declared |
| TP004 | requested scope exceeds delegated scope |
| TP005 | required approval is missing |
| TP006 | approval is not bound to the exact action |
| TP007 | executing agent differs from delegated agent |
| TP008 | revoked authority still produces an allow |
| TP009 | required step-up is incomplete |
| TP010 | declared child span has no parent evidence |
| TP011 | repeated denied action crosses the bounded retry threshold |
| TP012 | an expected consequential effect lacks a receipt |

Rules operate only on sanitized, declared evidence. Absence of a finding is not
proof that an undeclared event was safe or that instrumentation was complete.

## Privacy and custody boundary

The default policy is deny-by-default:

- content fields such as prompts, completions, tool arguments, and results are
  removed, not masked;
- common credential patterns are removed even if an attribute is allowlisted;
- principal, agent, tenant, approval, trace, and span identifiers are replaced
  with deterministic SHA-256 pseudonyms;
- arbitrary resource and span attributes are discarded unless allowlisted;
- a redaction summary reports removal counts without reproducing the values;
- imports are bounded to 50 MiB and 10,000 spans.

Pseudonymization is not anonymization. Stable hashes can preserve linkability,
and low-entropy identifiers may be guessable. Keep the policy salt, evidence,
and source telemetry inside the operator's approved data boundary. Review local
privacy, records, legal, and security requirements before retaining artifacts.

## Evidence and exports

Every evidence, report, and replay-twin artifact carries a canonical SHA-256.
`trace verify` recomputes structure, identifiers, findings, summaries, and
digests offline. SHA-256 supplies tamper evidence, not signer identity,
non-repudiation, or proof that the original exporter was trustworthy.

The OSCAL export is an Assessment Results input for an accountable workflow;
it is not a System Security Plan, assessment authorization, control
determination, certification, compliance decision, or authorization to
operate. See [NIST OSCAL](https://pages.nist.gov/OSCAL/about/) for the model's
intended document ecosystem.

The synthetic twin contains only the minimum sanitized event and finding shape
needed for replay-oriented regression work. It does not reproduce production
prompts, identities, data, timing, or infrastructure.

## Threat model and non-claims

TraceProof helps find authorization continuity, audience, scope, approval,
revocation, retry, and effect-receipt problems visible in declared telemetry.
It does not detect every prompt injection, validate an identity provider,
observe encrypted traffic, prove telemetry completeness, establish causality,
replace incident response, or authorize production operation. Run it only on
telemetry you are permitted to process.
