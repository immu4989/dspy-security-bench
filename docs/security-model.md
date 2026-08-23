# Repository and evidence security model

## Trust boundaries

Model/provider execution is untrusted. Benchmark-owned environments observe
functional state. Report verifiers recompute outcomes and statistics. Submission
bundles content-address the verified report. GitHub/Sigstore attestations can
add builder and workflow identity, but do not independently observe a hosted
model provider.

AuthorityAdapter implementations are also untrusted. AuthorityTwin owns the
synthetic request/context and simulated effect trace, while the adapter supplies
an allow, deny, or review decision plus a narrowly normalized receipt. Receipt
hashes prove benchmark-internal consistency, not identity-provider signature,
execution authenticity, or non-repudiation.

FederalProof trusts only a verified source bundle plus an explicitly
owner-supplied deployment profile. Its manifest detects file changes, but an
authorized reviewer must still assess truthfulness, representativeness, linked
OSCAL documents, and the real deployment.

InventoryForge treats public inventory records as potentially stale secondary
evidence. It ignores contact fields and never promotes the record into
controlling policy. Generated packs contain a labeled synthetic policy and
remain drafts until an accountable owner reviews and versions them.

AgentGraphTwin composes the AuthorityAdapter trust boundary over a benchmark-
owned fictional path. Its first-unsafe-edge and blast-radius fields describe
the frozen synthetic graph only. AuthorityBridge fixtures test response
translation and never establish that a named backend, SDK, policy, credential,
or deployment was executed correctly.

ContinuousProof trusts only evidence types whose local verifier succeeds. It
detects digest, identity, and numeric-metric changes but does not monitor a
production system or decide whether a regression is acceptable.
AcquisitionProof trusts an owner-supplied profile and verified snapshot. Its
manifest preserves bytes, not the truth or completeness of owner declarations.

## Threats addressed

- narrative-only scores hiding harmful tool side effects;
- modified summaries that disagree with nested action traces;
- unstable stochastic outcomes hidden by one successful run;
- evidence or policy files altered after evaluation;
- reference fixtures presented as model measurements;
- ambient credentials, identity substitution, scope/tenant/audience confusion,
  revoked or replayed authority, delegation inflation, and intent mismatch made
  invisible by clean task-success metrics;
- control mappings presented as automated compliance; and
- release supply-chain drift through unpinned GitHub Actions.
- contact data unintentionally copied from a public AI inventory into a test
  pack;
- authorization failures hidden inside a successful multi-agent terminal
  outcome;
- metric or protocol drift hidden by replacing a benchmark screenshot; and
- missing acquisition cost or outcome observations silently treated as passes.

## Threats not solved

- a malicious provider or evaluator fabricating the entire interaction trace;
- compromised runners, dependencies, maintainers, or signing identities;
- production-only behavior, distribution shift, insider abuse, or novel attacks;
- privacy, civil-rights, records, accessibility, legal, or mission authorization;
- safe integration with live operational tools;
- real token/key custody, identity proofing, authorization-service correctness,
  revocation latency, cryptographic provider receipts, or non-repudiation; and
- long-term availability of third-party services.
- completeness or currency of public inventories, mission-owner approval,
  procurement authority, price reasonableness, vendor portability, or the
  representativeness of a generated mission draft; and
- asynchronous graph races, graph-wide production blast radius, backend policy
  semantics beyond the normalized bridge contract, or continuous production
  telemetry.

Use least privilege, protected branches, required reviews, secret scanning,
artifact attestations, dependency review, CodeQL, Scorecard, SBOMs, reproducible
verification, and independent reproduction as complementary controls.
