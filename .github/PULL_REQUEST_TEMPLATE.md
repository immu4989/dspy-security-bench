## What changed

<!-- Explain the user or research problem this solves. -->

## Evidence

- [ ] Offline tests pass: `pytest tests/ -q`
- [ ] Ruff passes: `ruff check dspy_security_bench/ tests/`
- [ ] Generated artifacts were rebuilt from their committed sources
- [ ] New research claims include scope, limitations, and related work

## Cross-language interoperability

<!-- Delete this section if the PR does not add or change an interop runner. -->

- [ ] The implementation imports or executes neither an existing verifier nor its result
- [ ] The immutable vector corpus is unchanged, or a new version is explicitly proposed
- [ ] Output binds the exact implementation source and vector manifest digests
- [ ] All known-answer and self-rehashed differential cases pass offline
- [ ] A RootViewInteropEvidence report builds and reverifies from the retained source
- [ ] No private keys, credentials, production roots, endpoints, or controlled data are included
- [ ] The supported protocol subset and signature schemes are documented without certification claims

## Community evidence submission

<!-- Delete this section if the PR is not a community result. -->

- [ ] The matching offline verifier passes for `submissions/impact/`, `control/`, `incident/`, `source/`, `authority/`, `trace/`, `causal/`, `collective/`, or `defense/`
- [ ] Trial-based bundles contain at least five complete trials; TraceProof bundles recompute from sanitized evidence
- [ ] The source URL describes the evaluated agent configuration
- [ ] No raw OTLP, provider credentials, private prompts, tool arguments/results, identifiers, or sensitive production data are included
- [ ] Defense evidence contains only synthetic or sanitized structural state; no live targets, exploit payloads, or unpatched private vulnerability details are included
- [ ] ResilienceGraph campaigns use fictional/safely abstracted dependencies and label service mappings, weights, units, groups, and scenarios as owner-supplied assumptions
- [ ] I identified the evidence tier: self-attested / GitHub-attested / trusted builder
- [ ] I understand that provenance does not independently authenticate provider responses
