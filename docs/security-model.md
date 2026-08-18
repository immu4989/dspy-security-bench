# Repository and evidence security model

## Trust boundaries

Model/provider execution is untrusted. Benchmark-owned environments observe
functional state. Report verifiers recompute outcomes and statistics. Submission
bundles content-address the verified report. GitHub/Sigstore attestations can
add builder and workflow identity, but do not independently observe a hosted
model provider.

FederalProof trusts only a verified source bundle plus an explicitly
owner-supplied deployment profile. Its manifest detects file changes, but an
authorized reviewer must still assess truthfulness, representativeness, linked
OSCAL documents, and the real deployment.

## Threats addressed

- narrative-only scores hiding harmful tool side effects;
- modified summaries that disagree with nested action traces;
- unstable stochastic outcomes hidden by one successful run;
- evidence or policy files altered after evaluation;
- reference fixtures presented as model measurements;
- control mappings presented as automated compliance; and
- release supply-chain drift through unpinned GitHub Actions.

## Threats not solved

- a malicious provider or evaluator fabricating the entire interaction trace;
- compromised runners, dependencies, maintainers, or signing identities;
- production-only behavior, distribution shift, insider abuse, or novel attacks;
- privacy, civil-rights, records, accessibility, legal, or mission authorization;
- safe integration with live operational tools; or
- long-term availability of third-party services.

Use least privilege, protected branches, required reviews, secret scanning,
artifact attestations, dependency review, CodeQL, Scorecard, SBOMs, reproducible
verification, and independent reproduction as complementary controls.
