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
procurement policy. Saved schema-v2 reports can be explained offline.

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
