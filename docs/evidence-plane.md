# Agent Assurance Evidence Plane

The Agent Assurance Evidence Plane connects containment measurement, source
provenance, delegated identity, sector-specific review objectives, public
reproduction, and continuous drift into one offline-verifiable chain.

Its purpose is practical interoperability. Frontier AI teams, enterprises,
cybersecurity providers, technology partners, government agencies, assessors,
and critical-infrastructure operators can contribute different evidence sources
without surrendering raw prompts, model reasoning, credentials, tool payloads,
or production response authority.

## The connected chain

```text
runtime · identity · network · evaluator · response · control
                              │
                       EvidenceBridge
                              │
           CollectiveGuard v1 rules + v2 provenance gate
                              │
   ┌──────────────────────────┼──────────────────────────┐
   │                          │                          │
no violation observed  violations detected   insufficient evidence
   │                          │                          │
identity passport      adoption profile/OSCAL      owner review
   └──────────────────────────┼──────────────────────────┘
                 ContinuousProof observations
                              │
                    hash-chained timeline
```

The layers are separately versioned. CollectiveGuard v1 is frozen; v2 composes
it rather than changing existing findings or reports.

## 1. EvidenceBridge

EvidenceBridge accepts only a strict structural manifest:

- a validated CollectiveGuard v1 scenario;
- source class, adapter identity/version, collection status, clock domain, and
  SHA-256 identity;
- event-to-observation bindings;
- observed field names; and
- `observed`, `attested`, `asserted`, or `inferred` provenance.

Arbitrary telemetry records cannot survive the conversion. The bridge never
claims that a backend, collector, exporter, attester, or trust root is valid.
OpenTelemetry's GenAI agent semantic conventions remain marked Development, so
the bundled profile is correspondingly labeled and requires owner-maintained
field mappings.

## 2. Provenance gate

The v2 analyzer always recomputes the embedded v1 report. It then applies two
separate questions:

1. Did the supplied record contain a deterministic structural violation?
2. Is the supplied record complete enough to support a clean-result claim?

Violations remain visible with partial evidence. A clean result is withheld
when a required source is missing/partial or an event is unbound/assertion-only.
This prevents absence of telemetry from being mislabeled as absence of risk.

## 3. Agent Identity Passport

The passport is a content-addressed run envelope rather than a new credential.
It binds principal, agent, tenant, run, task, audience, scope, action, resource,
authorization receipt, nonce, effect receipt, delegation chain, expiry, and
revocation order. Verification checks:

- delegation continuity and authority attenuation;
- exact agent/run/task/audience/scope/action/resource binding;
- allow decision and lifetime before effect;
- verified revocation before effect;
- authorization nonce replay; and
- trust status kept distinct from content integrity.

```bash
dspy-security-bench authority passport describe
dspy-security-bench authority passport demo
dspy-security-bench authority passport init --out passport.json
dspy-security-bench authority passport run passport.json --out passport-report.json
dspy-security-bench authority passport verify passport-report.json
```

`trust_status: verified` is owner-supplied evidence state; the reference
protocol does not manufacture or validate external PKI, workload identity,
Sigstore, IAM, or authorization-service trust roots.

## 4. Adoption profiles and OSCAL

The built-in profiles cover enterprise, frontier-lab, federal-high-impact, and
critical-infrastructure contexts. They define required source classes, maximum
escalation/containment objectives, independent containment, evidence
preservation, and local control objectives.

Mappings to NIST CSF 2.0, AI RMF functions, and incident-response stages are
high-level and informative. Exported OSCAL Assessment Results carry
`mapping-status: informative-not-determinative` and `non-certifying: true`.
System owners must replace defaults with the applicable law, policy, risk,
mission, authorization boundary, data classification, Assessment Plan, SSP,
and accountable decision process.

## 5. Public evidence registry

The [CollectiveGuard registry](../submissions/collective/README.md) accepts
content-addressed v2 bundles. Pull-request CI recomputes the v1 report, v2
coverage and provenance, report digest, scenario binding, and outer bundle
digest. Unsafe evidence can be valid. An incomplete clean claim is not eligible.

## 6. Continuous assurance without autonomous response

The observe-only controller reads owner-selected files below an explicit root,
verifies supported evidence, evaluates age and regression thresholds, and emits
review evidence. It cannot execute containment. Longitudinal entries are linked
by hash, but external signatures and trusted timestamps remain deployment-owned.

## Standards and research basis

This design follows the direction—not a claim of conformance—of:

- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative), including secure interoperability, identity/authorization, and security evaluation;
- [NIST AI 800-2 initial public draft](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.800-2.ipd.pdf), which separates measurement targets, implementations, runs, analysis/reporting, uncertainty, and reproducibility;
- [NIST IR 8607](https://csrc.nist.gov/pubs/ir/8607/final), on AI system cybersecurity, evolving attack surfaces, terminology, use cases, and control overlays;
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), on integrating incident response with cybersecurity risk management;
- [NCCoE software and AI agent identity and authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization);
- [OpenTelemetry GenAI agent span conventions](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md); and
- [OWASP Agentic AI threats and mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/).

The project does not claim this combination has never been attempted elsewhere.
Its falsifiable contribution is the shipped protocol: strict schemas, explicit
claim boundaries, deterministic fixtures, offline recomputation, adversarial
tests, public registry admission, and connected CLI workflows.
