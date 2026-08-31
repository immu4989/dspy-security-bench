# AssuranceQuorum: no single signature can manufacture trust

AssuranceQuorum turns an AssuranceGraph report into role-separated,
cryptographically verifiable review evidence. It answers:

> Did every claim receive the required evidence review from authorized,
> separately governed functions—and did any reviewer record a gap?

It does not collect deployment approvals. Reviewers sign one of three bounded
statements for assigned claims:

- `evidence-sufficient` — the signer found the referenced evidence sufficient
  for the frozen claim predicates;
- `evidence-gap` — the signer found a review gap, which cannot be outvoted; or
- `abstain` — the signer makes no sufficiency statement.

Every statement is an [in-toto Statement
v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
inside a [DSSE
envelope](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md),
signed with an authorized Ed25519 key. The statement binds the exact
AssuranceGraph report digest, quorum-policy digest, case, profile, reviewer role,
organization identifier, assigned claims, decision, reason codes, and review
window.

## Five-minute complete demo

```bash
git clone https://github.com/immu4989/dspy-security-bench.git
cd dspy-security-bench
uv sync --locked --extra dev --extra signing

uv run dspy-security-bench quorum demo --out-dir artifacts/assurance-quorum
uv run dspy-security-bench quorum verify \
  artifacts/assurance-quorum/quorum-satisfied.report.json \
  --evidence-root artifacts/assurance-quorum
```

The fictional demo generates its private keys only inside a temporary directory
and discards them. The published demo artifacts include:

```text
assurance-quorum/
├── assurance-case.json
├── assurance-report.json
├── quorum-policy.json
├── quorum-satisfied.report.json
├── quorum-satisfied.sarif
├── review-gap.report.json
├── review-gap.sarif
├── evidence/                  # nine natively verified synthetic reports
└── reviews/                   # five role-scoped DSSE envelopes
```

`quorum-satisfied` and `review-gap-recorded` are protocol fixtures, not findings
about an organization, product, model, or government system.

## The trust layers remain separate

| Layer | What is verified | What is not established |
|---|---|---|
| AssuranceGraph | Native evidence, predicates, freshness, ownership, and exact case content | Truth of external observations or permission to deploy |
| Ed25519 + DSSE | Possession of a private key and exact signed statement bytes | Human identity, competence, role, or independence |
| Quorum policy | Whether the key is authorized for a declared signer, role, and organization | External key governance or employment status |
| Claim quorum | Whether all required roles, signer counts, and distinct-organization counts support the evidence | Safety, compliance, ATO, procurement approval, or risk acceptance |

This distinction follows SLSA's principle that provenance has value only when a
consumer verifies it against explicit expectations. It also follows NIST's
distinction between first-, second-, and third-party attestations: which party
made a statement is a policy question, not a property inferred from a signature.

## Create a real organization-owned quorum

Generate a separate keypair for every reviewer. Keep private keys outside the
repository and use your normal key custody, rotation, and revocation process.

```bash
dspy-security-bench quorum keygen \
  --private-key keys/security.private.pem \
  --public-key keys/security.public.pem
```

Create a policy bound to an already complete AssuranceGraph report. Repeat
`--reviewer` for each authorized signer:

```bash
dspy-security-bench quorum policy-init assurance-report.json \
  --evidence-root . \
  --policy-id agency-pilot-review \
  --title "Agency pilot evidence review" \
  --preset federal-separation \
  --not-before 1788048000 --not-after 1788134400 \
  --reviewer "signer_id=security-reviewer-1,role=security-reviewer,organization_id=agency-security,public_key=keys/security.public.pem" \
  --reviewer "signer_id=independent-reviewer-1,role=independent-reviewer,organization_id=independent-lab,public_key=keys/independent.public.pem" \
  --out quorum-policy.json
```

The `federal-separation` engineering preset routes claims by function:

- evaluation integrity → evaluation owner + independent reviewer;
- observability → privacy reviewer + security reviewer;
- remediation and resilience → mission owner + independent reviewer; and
- remaining authority, containment, schedule, and dependency claims → security
  reviewer + independent reviewer.

Every claim requires both assigned roles and at least two distinct declared
organizations. These are owner-selectable engineering defaults, not a federal
control baseline or government requirement. `independent-two-party` assigns a
system owner and independent reviewer to every claim.

## Sign a scoped review

```bash
dspy-security-bench quorum sign quorum-policy.json assurance-report.json \
  --evidence-root . \
  --private-key keys/security.private.pem \
  --signer-id security-reviewer-1 \
  --decision evidence-sufficient \
  --claims bounded-authority,runtime-containment,dependency-boundary-current \
  --reason-code native-verification-reviewed \
  --reason-code claim-predicates-reviewed \
  --issued-at 1788048100 --expires-at 1788134300 \
  --out reviews/security.dsse.json
```

The signer cannot claim a role, key, subject, policy, or claim assignment not
authorized by the policy. Unknown predicate fields, non-canonical JSON,
non-Ed25519 keys, changed payloads, stale statements, and invalid signatures
fail closed.

## Evaluate and preserve objections

```bash
dspy-security-bench quorum evaluate \
  quorum-policy.json assurance-report.json reviews/*.dsse.json \
  --evidence-root . --evaluation-time 1788048200 \
  --out assurance-quorum.report.json \
  --sarif-out assurance-quorum.sarif \
  --fail-on-review
```

| Outcome | Exact meaning |
|---|---|
| `quorum_satisfied` | Every claim has evidence-sufficient statements from all required roles, enough unique signers, and enough distinct declared organizations. |
| `review_gap_recorded` | At least one valid, assigned reviewer signed an evidence-gap statement. Additional supporting statements cannot erase it. |
| `quorum_incomplete` | No gap takes precedence, but a role, signer, or organization requirement is missing. |
| `invalid_review_evidence` | At least one envelope is invalid or one signer submitted multiple valid statements for the same policy. |

The report embeds the policy, source AssuranceGraph report, and DSSE envelopes
for exact recomputation. Native AssuranceGraph verification still requires the
local evidence root; a signature never upgrades arbitrary JSON into evidence.

## Why organizations can use this

- **Government programs** can require technical, mission, privacy, evaluation,
  and independent-review functions without letting a single official or vendor
  signature stand in for an authorization decision.
- **Frontier labs** can bind evaluator-integrity review separately from system
  ownership and independent challenge.
- **Cybersecurity companies** can issue scoped, portable review statements
  without receiving authority over the customer's deployment.
- **Technology partners** can interoperate through in-toto/DSSE rather than a
  repository-specific opaque signature blob.
- **Executives and auditors** see gaps, missing roles, invalid signatures, and
  conflicting governance as distinct outcomes instead of one green badge.

The envelope model is compatible with the direction of the [in-toto Attestation
Framework](https://github.com/in-toto/attestation), [SLSA verification
expectations](https://slsa.dev/spec/v1.2/verifying-artifacts), and [Sigstore's
portable verification bundles](https://docs.sigstore.dev/about/bundle/).
AssuranceQuorum itself verifies local policy-authorized Ed25519 keys. The
separate [AssuranceLedger](assuranceledger.md) can add witnessed append-only
registration, review inclusion, retirement, and compromise evidence. It remains
a repository-native protocol—not Sigstore identity or Rekor verification.

## Explicit non-claims

AssuranceQuorum does not establish:

- reviewer legal identity, employment, competence, or independence;
- key custody, freshness beyond the declared window, rotation, or revocation;
- completeness or truth of observations outside native evidence verification;
- model safety, alignment, robustness, legal compliance, or fitness for use;
- satisfaction of a NIST, OMB, agency, sector, or contractual requirement; or
- approval, certification, ATO, procurement selection, deployment authority,
  restart authority, funding decision, or risk acceptance.

Accountable organizations must govern reviewer identities and keys, tailor the
policy, resolve every gap, and make every consequential decision themselves.
