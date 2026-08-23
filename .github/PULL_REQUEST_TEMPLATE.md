## What changed

<!-- Explain the user or research problem this solves. -->

## Evidence

- [ ] Offline tests pass: `pytest tests/ -q`
- [ ] Ruff passes: `ruff check dspy_security_bench/ tests/`
- [ ] Generated artifacts were rebuilt from their committed sources
- [ ] New research claims include scope, limitations, and related work

## Community evidence submission

<!-- Delete this section if the PR is not a community result. -->

- [ ] The matching offline verifier passes for `submissions/impact/`, `control/`, `incident/`, `source/`, `authority/`, or `trace/`
- [ ] Trial-based bundles contain at least five complete trials; TraceProof bundles recompute from sanitized evidence
- [ ] The source URL describes the evaluated agent configuration
- [ ] No raw OTLP, provider credentials, private prompts, tool arguments/results, identifiers, or sensitive production data are included
- [ ] I identified the evidence tier: self-attested / GitHub-attested / trusted builder
- [ ] I understand that provenance does not independently authenticate provider responses
