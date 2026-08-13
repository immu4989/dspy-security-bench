# Research and repository audit — August 2026

This note records why the next contribution focused on actionable evidence and
benchmark integrity instead of adding another broad attack-success benchmark.
It is a dated prioritization record, not an exhaustive systematic review.

## Evidence reviewed

- [NIST AI 800-5](https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai)
  reports broad agreement that agent-security concerns impede adoption and that
  existing cybersecurity practices need adaptation.
- [NIST evaluation probes](https://www.nist.gov/programs-projects/building-evaluation-probes-agentic-ai)
  call for increased visibility into tool usage and machine-readable audit
  trails that connect agent decisions to evidence.
- [MPBench](https://arxiv.org/abs/2606.04329),
  [stored prompt injection](https://arxiv.org/abs/2606.04425), and
  [Bad Memory](https://arxiv.org/abs/2607.14611) already provide substantial
  2026 coverage of memory poisoning and cross-session persistence.
- [Counterfactual Trace Auditing](https://arxiv.org/abs/2605.11946) shows why
  paired traces reveal behavioral changes hidden by endpoint pass rates.
- [ContainmentBench](https://arxiv.org/abs/2607.23999) separately measures
  terminal outcomes, trace propagation, recovery evidence, and useful action.

## Repository audit

The repository already measured functional end state, but users still had to
manually reconstruct where a clean/poisoned execution diverged and which policy
boundary could contain it. Three integrity problems were also visible:

1. the public CI matrix was red on Python 3.10 and 3.11 because resource tests
   relied on newer `Traversable.joinpath` behavior; and
2. open issue #2 demonstrated that newline- and tab-separated payloads passed
   through `spotlight_datamark` without a single marker; and
3. CI, Pages, and release workflows used mutable, outdated action tags, leaving
   a security-focused project with avoidable supply-chain drift and Node 20
   deprecation warnings.

A new generic memory benchmark would therefore duplicate fast-moving work while
leaving immediate trust and usability gaps unresolved.

## Selected contribution

**BoundaryDiff** adds environment-owned action traces to ImpactTwin, locates the
first event-level divergence, reports poisoned-only events and functionally
observed harms, and maps the failure to an executable rule in the packaged
procurement policy. Saved schema-v3 reports can be explained offline.

Acceptance criteria:

- scoring never depends on a model's self-reported trace;
- all five vulnerable fixtures produce a localized divergence and applicable
  control, while all bounded twins remain trace-equivalent;
- JSON schema and SARIF preserve the new evidence;
- stochastic single-pair limitations are explicit;
- Python 3.10–3.14 tests pass; and
- multiline datamarking is mechanically regression-tested.

The repository workflows are also upgraded to current Node 24 action releases,
pinned by full commit SHA, with a fixed uv version for repeatable CI setup. The
matrix covers Python 3.10–3.14 without installing the optional PyTorch-based
synthesis stack in every job.

This work does not claim that trace auditing, counterfactual comparison, memory
security, or least privilege is individually novel. Its value is an integrated,
reproducible path from public-interest failure to inspectable evidence and a
deployable authority boundary.

## Follow-on: repeated-execution evidence

The August 12 follow-on addresses the audit's remaining statistical limitation:
a single paired run cannot establish stable behavior for a stochastic agent.
RepeatTwin retains multiple complete trials, reports Wilson score intervals for
each fixed attack pair and the aggregate fixed suite, exposes outcome-class
instability and runtime errors, and preserves optional provider token/cost
telemetry. The sampling unit is declared as `fixed_suite_pair_trial`; no claim
is made that five frozen scenarios represent an unseen procurement-task
population.

Community bundles add recomputable statistics and canonical content hashes.
They are deliberately labeled self-attested: tamper evidence is not execution
provenance. This follows the same trust-boundary discipline as BoundaryDiff—say
exactly which evidence the system owns, and do not silently upgrade a checksum
into a stronger claim.

## Follow-on: ProofRun provenance

A second landscape check reviewed contemporary prompt-injection evaluation
platforms including [PIArena](https://github.com/sleeepeer/PIArena), benchmark
reproducibility work such as
[redharness](https://github.com/MohamedAklamaash/redharness), NIST's call for
machine-readable agent-evaluation audit trails, GitHub artifact attestations,
and the [SLSA v1.2 verification model](https://slsa.dev/spec/v1.2/verifying-artifacts).
The reviewed benchmark projects preserve configurations, transcripts, or
content-addressed evidence. This dated, non-systematic search did not identify a
prompt-injection benchmark that also provides all of the following as one
contribution path:

- repeated counterfactual agent trials with an explicit estimand and confidence
  lower-bound gate;
- offline recomputation from preserved raw functional outcomes;
- an in-toto/Sigstore attestation over the exact result artifact;
- verifier policy for repository, commit, ref, hosted runner, and signer
  workflow; and
- distinct public tiers for content integrity, caller-workflow provenance,
  central-builder provenance, and independent reproduction.

ProofRun implements that integration without claiming that its ingredients are
individually novel. The trusted workflow separates the untrusted evaluation job
from a clean verification/signing job: provider credentials are available only
to evaluation, while OIDC signing authority is available only after the frozen
engine recomputes the downloaded bundle. This follows SLSA's core separation
between a tenant-controlled process and the control plane that records
provenance.

The boundary remains explicit. A valid attestation proves that a named workflow
produced exact bytes from a named source commit. It cannot prove that a remote
provider returned the embedded response, that evaluated source code is honest,
or that five synthetic procurement pairs establish deployment safety. The
dashboard therefore requires a reviewed, digest-keyed registry before showing a
cryptographic tier; an unverified provenance claim is displayed as pending.
