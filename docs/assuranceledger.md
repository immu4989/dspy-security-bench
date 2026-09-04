# AssuranceLedger: trust can expire, and logs need witnesses

AssuranceLedger adds witnessed, append-only reviewer-key lifecycle evidence to
AssuranceQuorum. It answers three questions that a valid DSSE signature alone
cannot answer:

1. Was the review and its reviewer-key registration present in the same
   committed log view?
2. Did separately governed witnesses observe that exact append-only checkpoint?
3. Has a later revocation retired the key or retrospectively invalidated the
   review because the declared compromise began before signing?

The protocol distinguishes a currently trusted review, a historically valid
review from a now-retired key, a review invalidated by a declared compromise,
incomplete trust evidence, and invalid ledger evidence. It never silently turns
missing lifecycle evidence into current trust.

## Five-minute offline demonstration

```bash
uv sync --locked --extra dev --extra signing

dspy-security-bench ledger demo --out-dir artifacts/assurance-ledger
dspy-security-bench ledger verify \
  artifacts/assurance-ledger/current-trust.report.json \
  --evidence-root artifacts/assurance-ledger/quorum
```

The fictional demo generates all operator and witness private keys inside a
temporary directory and discards them. It produces two complete cases:

- `current-trust.report.json` — five DSSE reviews have prior registrations,
  exact log entries, Merkle inclusion paths, and a checkpoint signed by the log
  operator plus two witnesses from distinct fictional organizations; and
- `compromise-invalidation.report.json` — an append-only extension records a
  fictional independent-reviewer compromise whose declared start predates that
  review, invalidating it without deleting history or taking an automatic
  action.

These are protocol fixtures, not findings about a person, organization, key,
product, model, or government system.

The demo also writes `forked-view.report.json` and
`view-comparison.report.json`. The two self-consistent views contain valid
operator and witness signatures at the same tree size but commit to different
roots. Comparing them produces `equivocation_evidenced`; neither history is
silently selected as authoritative.

It additionally writes `fork-proof.report.json`: a standalone proof of that
same-size conflict with no embedded ledger entries or review content.

The same command now produces the complete partner-verification surface:

- `capability-manifest.json` — eleven offline protocol contracts and sixteen
  exact schema digests;
- `trust-root-v1.json` through `trust-root-v3.json`, `trust-root.report.json`,
  and `trust-root-chain.report.json` — a pinned predecessor, dual-threshold
  rotation, and stale-client multi-hop catch-up;
- `integration-lock.json` and `integration-lock-check.report.json` — the
  owner-pin fixture and zero-drift reference result;
- `verifier-conformance.report.json` — eleven clean-source-validated, rehashed
  adversarial rejection cases; and
- SARIF companions for ledger outcomes, gossip, compact proofs, observation,
  witness attribution, re-review, conformance, and integration drift.

The reference directory is intentionally verbose so a reviewer can inspect
every intermediate artifact. Production deployments should retain only the
artifacts their policy and data-handling boundary require.

## Evidence chain

```text
AssuranceQuorum DSSE review
       │ exact envelope SHA-256
       ▼
review log event ◀── prior reviewer-key registration
       │
       ▼ RFC 6962-style 0x00 leaf / 0x01 node hashing
operator-signed Merkle checkpoint
       │
       ├── witness A signature · organization A
       └── witness B signature · organization B
       │
       ▼ append-only prefix recomputation
later checkpoint ── optional retirement / compromise declaration
```

Every event has a contiguous sequence, monotonic integration time, strict body,
and canonical content hash. A checkpoint binds the policy, log origin, tree
size, Merkle root, issue time, and prior checkpoint size/root. The verifier
recomputes the complete tree, prior prefix, operator signature, every witness
signature, witness and organization thresholds, source AssuranceQuorum report,
registrations, review metadata, revocations, and per-review inclusion paths.

AssuranceLedger uses the domain-separated Merkle construction described by
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) and is informed by
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162), where inclusion and
consistency proofs make append-only log behavior auditable. Its witness model is
informed by the [C2SP transparency-log witness
protocol](https://c2sp.org/tlog-witness), in which witnesses verify consistency
before cosigning checkpoints. Its explicit consumer policy follows the trust-
root discipline used by [Sigstore](https://docs.sigstore.dev/about/bundle/) and
[TUF](https://theupdateframework.github.io/specification/).

This implementation is intentionally a small, self-contained assurance
protocol. It is **not** a Certificate Transparency, Rekor, C2SP signed-note,
C2SP witness, or TUF wire-format implementation.

## Establish and rotate the authority behind the policy

Witnessed checkpoints still need a trusted answer to “which operator, witness,
observer, reviewer, and policy keys are authoritative?” AssuranceTrustRoot adds
that missing layer:

```bash
# Recompute the fictional v1 → v2 rotation embedded by `ledger demo`.
dspy-security-bench ledger verify-trust-root \
  artifacts/assurance-ledger/trust-root.report.json

# Evaluate an organization-owned exact successor against persisted trusted state.
dspy-security-bench ledger evaluate-trust-root root-v2.json \
  --trusted-root root-v1.json \
  --expected-domain agency-ai-assurance \
  --minimum-version 2 \
  --evaluation-time 1788134500 \
  --policy ledger-policy.json \
  --out root-rotation.report.json \
  --sarif-out root-rotation.sarif \
  --fail-on-trust
```

A first root is trusted only against an independently supplied exact digest.
Each successor must be the next version, bind the complete predecessor root,
and carry enough valid signatures and declared organizations under **both** the
old and new root roles. Exact policy digests prevent a friendly name from
quietly authorizing changed bytes. Expiration exposes a possible freeze or
missed rotation without pretending to know the cause.

The root format explicitly supports Ed25519, ECDSA P-256/SHA-256, and RSA-PSS/
SHA-256 so an owner can perform a verified classical-algorithm migration. It
does not claim post-quantum protection, FIPS validation, secure private-key
custody, or TUF compatibility. See the complete [AssuranceTrustRoot operator
guide](assurancetrustroot.md).

Long-lived or intermittently connected clients can verify every missed
rotation without treating an expired intermediate as current authority:

```bash
dspy-security-bench ledger evaluate-trust-chain \
  root-v1.json root-v2.json root-v3.json \
  --expected-root-sha256 "$REVIEWED_ROOT_V1_SHA256" \
  --minimum-final-version 3 \
  --evaluation-time 1819700000 \
  --out trust-root-chain.report.json \
  --sarif-out trust-root-chain.sarif \
  --fail-on-trust
```

TrustRootChain verifies both thresholds at every exact successor hop, caps the
input at 64 roots, records algorithm transitions, and requires the final root
to be issued and unexpired. The minimum-version input can expose a known
truncated prefix; no offline proof can discover a newer root that is withheld.

## Outcomes with non-overlapping meanings

| Outcome | Exact meaning |
|---|---|
| `reviewer_trust_current` | Every valid source review is logged exactly once, has one earlier registration valid at issuance, is covered by the witnessed fresh checkpoint, and has no effective revocation. |
| `reviewer_trust_historical` | The review was valid at issuance, but the key is now retired without a declared compromise that reaches back to signing. |
| `reviewer_trust_invalidated` | A logged revocation declares `compromise_since` at or before review issuance. |
| `trust_evidence_incomplete` | A review, exact log entry, or valid-at-issuance registration is missing or ambiguous. |
| `invalid_ledger_evidence` | The source quorum, Merkle root, append-only prefix, checkpoint freshness, operator signature, witness signature, or witness threshold is invalid. |

Historical retirement is not retroactive compromise. Keeping those states
separate lets auditors preserve legitimate historical evidence while requiring
new reviews for current decisions. A `compromise_since` declaration is more
severe and invalidates affected reviews; it is an accountable operator claim,
not a fact inferred by this software.

## Exchange checkpoints to detect a split view

A self-consistent log cannot demonstrate that everybody received the same
history. Compare reports obtained through separately governed channels:

```bash
dspy-security-bench ledger compare \
  observer-a/assurance-ledger.report.json \
  observer-b/assurance-ledger.report.json \
  --evidence-root artifacts/assurance-quorum \
  --out checkpoint-comparison.report.json \
  --sarif-out checkpoint-comparison.sarif \
  --fail-on-fork

dspy-security-bench ledger verify-comparison \
  checkpoint-comparison.report.json \
  --evidence-root artifacts/assurance-quorum
```

Every input first passes full AssuranceLedger and AssuranceQuorum semantic
recomputation. For one log origin and policy, the analyzer compares every pair:

- an older event history that exactly matches the newer history's prefix is
  `consistent_prefix`;
- valid signed checkpoints at the same size with different roots, or histories
  that diverge before the smaller size, are `equivocation_evidenced`;
- repeated copies of one checkpoint are `insufficient_view_diversity`; and
- a bad signature, tree, prefix, source quorum, or mixed log identity is
  `invalid_view_evidence`, never fork proof.

This follows RFC 6962's core gossip insight: conflicting signed tree heads from
one log provide evidence of operator misbehavior. The implementation embeds
complete bounded histories for deterministic offline comparison rather than
implementing the RFC's compact consistency-proof wire protocol. A
`views_consistent` result applies only to the supplied files; undisclosed views
remain outside the claim boundary.

## Bind each view to an independent observer receipt

A file digest alone does not prove that two views arrived through independently
governed channels. An observer can sign a privacy-bounded receipt after native
ledger verification:

```bash
dspy-security-bench ledger observe observer-a/ledger.report.json \
  --observer-policy observer-policy.json \
  --observer-private-key observer-a.private.pem \
  --observer-id observer-a \
  --channel-class offline-transfer \
  --channel-locator private-airgap-drop-17 \
  --observed-at 1788048400 \
  --evidence-root artifacts/assurance-quorum \
  --out observer-a.receipt.json

dspy-security-bench ledger compare-receipts \
  observer-a.receipt.json observer-b.receipt.json \
  --observer-policy observer-policy.json \
  --ledger-policy ledger-policy.json \
  --out observer-comparison.report.json \
  --sarif-out observer-comparison.sarif \
  --fail-on-fork
```

Each receipt binds an observer key and declared organization, observation time,
source-report digest, exact signed checkpoint, channel class, and SHA-256 of the
private channel locator. The locator itself is never written. The analyzer
verifies observer, operator, and witness signatures, bounded delay, unique
observers, distinct declared organizations, and distinct channel digests before
emitting `independently_observed_equivocation`.

This JSON/Ed25519 protocol is informed by the portable signed-receipt and
sensitive-statement-hash principles in the IETF [SCITT architecture, RFC
9943](https://www.rfc-editor.org/rfc/rfc9943.html). It is not a COSE, CBOR,
SCITT, or SCRAPI implementation. Observer identity, organization, and channel
independence remain accountable policy assertions rather than facts discovered
by the software.

## Attribute witness keys that signed both fork views

The C2SP witness protocol requires a witness to reject same-size checkpoints
with different roots. After ForkProof verifies the operator conflict, identify
whether any policy witness keys nevertheless signed both views:

```bash
dspy-security-bench ledger analyze-witness-conflict \
  fork-proof.report.json \
  --out witness-conflict.report.json \
  --sarif-out witness-conflict.sarif

dspy-security-bench ledger verify-witness-conflict \
  witness-conflict.report.json
```

The analyzer intersects exact `(signer_id, keyid)` pairs across the two already
verified checkpoint signature sets. `operator_and_witness_conflict_evidenced`
means at least one witness key signed both conflicting views;
`operator_conflict_without_shared_witness` means none did. Attribution is to a
policy key and declared organization—not a person, intent, or legal entity. The
tool does not determine whether the cause was compromise, failure, collusion,
or misuse and performs no notification or revocation.

## Prove your verifier rejects rehashed tampering

Technology partners and agency integration teams can run the same adversarial
matrix after generating the complete fictional demo or placing equivalent valid
artifacts in one directory:

```bash
dspy-security-bench ledger conformance artifacts/assurance-ledger \
  --evidence-root artifacts/assurance-ledger/quorum \
  --out verifier-conformance.report.json \
  --sarif-out verifier-conformance.sarif \
  --fail-on-miss

dspy-security-bench ledger verify-conformance \
  verifier-conformance.report.json \
  --artifact-dir artifacts/assurance-ledger \
  --evidence-root artifacts/assurance-ledger/quorum
```

The runner changes a security-relevant field, recomputes the outer report hash,
and requires the intended deeper verifier rejection for eleven surfaces:
checkpoint signature binding, gossip outcome, re-review impact, ForkProof root,
ConsistencyProof path, ObserverReceipt signature, and witness-conflict
attribution, plus TrustRoot threshold signatures, TrustRootChain hop counts,
CapabilityManifest contract drift, and IntegrationLockCheck outcome drift. The
report binds every source artifact digest and recomputes exactly from the same
inputs.

Before applying any mutation, v4 runs all eleven clean artifacts through their
native verifiers. One already-invalid source aborts the matrix and cannot be
counted as an expected adversarial rejection. This makes “clean source” an
enforced experimental precondition rather than a caller assertion.

SARIF emits no result when all expected rejections occur. Each missed rejection
becomes stable rule `ALC001`, with the artifact kind, mutation digest, and actual
verifier errors available to code-scanning systems; it never remediates or
changes the verifier automatically.

This is a finite conformance matrix, not a security proof, fuzzing campaign,
interoperability certification, or government endorsement. It is designed to
give forks and independent implementations a stable rejection floor they can
run in CI without a network or live target.

## Discover the exact integration contract

An integration should not have to scrape documentation or assume that a package
version implies a particular artifact surface. Emit the deterministic local
capability manifest and verify it against the exact schemas installed beside the
package:

```bash
dspy-security-bench ledger capabilities \
  --out capability-manifest.json

dspy-security-bench ledger verify-capabilities \
  capability-manifest.json

# Optional when validating a checked-out or vendor-supplied schema directory.
dspy-security-bench ledger verify-capabilities \
  capability-manifest.json \
  --schema-root dspy_security_bench/schemas
```

The manifest covers eleven protocol surfaces and all sixteen AssuranceLedger
Draft 2020-12 schemas. Each schema record binds its stable `$id` and exact file
bytes with SHA-256. Each protocol record exposes its report type, producer and
verifier commands, whether verification is standalone, whether an evidence root
is required, the embedded data classes an integrator should review,
`network_required: false`, and `automatic_actions: 0`. The verifier recomputes
the entire document; changing a capability and merely replacing the outer hash
does not pass.

This follows JSON Schema's stable identifier and explicit-dialect model; it does
not register or claim a network `/.well-known/` location. RFC 8615 requires
application-specific registration and careful origin scoping for that form of
remote discovery. CapabilityManifest is therefore a local, byte-bound contract,
not protocol negotiation, service authentication, or interoperability
certification.

- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
- [RFC 8615 well-known URI scoping](https://www.rfc-editor.org/rfc/rfc8615.html)

### Pin an owner-reviewed compatibility floor

After review, preserve the exact minimum integration contract in source control
or an owner-governed artifact store, then check every candidate upgrade in CI:

```bash
dspy-security-bench ledger lock-capabilities \
  capability-manifest.json \
  --out integration-lock.json

dspy-security-bench ledger check-capability-lock \
  integration-lock.json candidate-capabilities.json \
  --out integration-lock-check.report.json \
  --sarif-out integration-lock-check.sarif \
  --fail-on-drift

dspy-security-bench ledger verify-capability-lock \
  integration-lock-check.report.json \
  integration-lock.json candidate-capabilities.json
```

IntegrationLock pins every schema digest and the protocol's report type,
artifact schemas, verifier command, standalone/evidence-root requirements,
offline boundary, automatic-action count, and disclosed data classes. Additive
capabilities are allowed. A removed protocol, changed pin, or schema-byte drift
produces a specific finding and nonzero CI exit when requested. The check report
binds the lock and candidate digests and recomputes exactly. SARIF assigns stable
rules to invalid locks, invalid candidates, schema drift, missing protocols, and
protocol-contract drift for code-scanning ingestion.

The lock is intentionally unsigned. Its authority comes only from the owner's
existing review and artifact-governance process; generating it is not evidence
that anyone reviewed or approved it. A satisfied check is compatibility evidence
for those pins, not vulnerability analysis, deployment authorization, or an ATO.

The repository's `AssuranceLedger trust and interoperability` workflow executes
this chain on every relevant pull request with read-only repository permission,
SHA-pinned actions, lockfile-only dependencies, no provider credential, and no
networked target. It preserves the generated JSON and SARIF bundle for 14 days
so reviewers can inspect the exact evidence even when a gate fails.

## Disclose the conflict without disclosing the review history

Full ledger reports can contain reviewer identifiers, exact review-envelope
digests, and lifecycle events that an incident recipient does not need. Once a
same-size conflict has passed full gossip verification, minimize it:

```bash
dspy-security-bench ledger export-fork-proof \
  checkpoint-comparison.report.json \
  --evidence-root artifacts/assurance-quorum \
  --out fork-proof.report.json \
  --sarif-out fork-proof.sarif

# No source reports or evidence directory are needed for this check.
dspy-security-bench ledger verify-fork-proof fork-proof.report.json
```

ForkProof retains the policy's operator and witness public keys, two signed
checkpoints, and three source digests. The standalone verifier checks exact log
origin and policy binding, equal positive tree size, different roots, two valid
operator signatures, both witness quorums, strict fields, and the report hash.
It embeds zero log entries, AssuranceQuorum reports, review envelopes, and
reviewer-key registrations.

The proof is deliberately limited to same-size conflicts. A different-size
divergence needs the full histories used by AssuranceLedger Gossip or a compact
consistency-proof protocol. The artifact proves operator-key misbehavior; it
does not determine which view is true or why the conflict happened. This
implements the portable evidence property described in [RFC 6962 section
7.3](https://www.rfc-editor.org/rfc/rfc6962#section-7.3), while the witness
quorum follows the consistency-before-cosigning model of the [C2SP witness
protocol](https://c2sp.org/tlog-witness).

## Prove legitimate growth without sharing log entries

The complementary case is a newer checkpoint that legitimately extends an
older tree. Export the unique minimal RFC 6962-style consistency path after
both complete source reports pass native verification:

```bash
dspy-security-bench ledger export-consistency-proof \
  older-ledger.report.json \
  newer-ledger.report.json \
  --evidence-root artifacts/assurance-quorum \
  --out consistency-proof.report.json \
  --sarif-out consistency-proof.sarif

# The recipient needs only this portable artifact.
dspy-security-bench ledger verify-consistency-proof \
  consistency-proof.report.json
```

The standalone verifier checks the embedded policy, both operator signatures,
both witness quorums, strict older/newer size ordering, and the domain-separated
Merkle path. The same nodes must reconstruct both signed roots. The artifact
contains zero ledger entries, AssuranceQuorum reports, reviewer registrations,
or review envelopes.

This follows the generation and verification construction in [RFC 9162 section
2.1.4](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.4). It is an
AssuranceLedger canonical-JSON proof format, not a CT `TransItem` or C2SP wire
artifact. A successful result is bounded to the two checkpoints; a missing or
failed proof is not automatically labeled equivocation, and global consistency
still requires independent checkpoint exchange.

## Reopen only the claims that lost trusted review

After retirement, compromise, or incomplete lifecycle evidence, compute the
smallest claim/role re-review set instead of restarting every review:

```bash
dspy-security-bench ledger plan-rereview \
  compromise-invalidation.report.json \
  --evidence-root artifacts/assurance-quorum \
  --historical-policy require-current-key \
  --out rereview-plan.report.json \
  --sarif-out rereview-plan.sarif \
  --fail-on-review

dspy-security-bench ledger verify-rereview \
  rereview-plan.report.json \
  --evidence-root artifacts/assurance-quorum
```

The planner recomputes the entire ledger, decodes the already-verified signed
claim assignments, and excludes only invalidated, incomplete, or owner-
disallowed historical reviews. It groups affected claims by required role and
reason. The reference compromise invalidates one independent-review statement
covering eight claims, so the result is one request for that role and those
eight claims—not nine blanket reviews.

`require-current-key` treats routine retirement as requiring re-review.
`allow-until-review-expiry` preserves the historical review until its signed
expiry but reports `renewal_due`. That switch records owner policy; it is not a
recommendation. Valid evidence-gap statements remain unresolved and cannot be
cleared by a replacement favorable signature. The planner selects no person,
takes no deployment action, and makes no authorization decision.

This narrowly operationalizes NIST AI RMF Core themes of ongoing monitoring,
periodic review, clear roles, and change management. The mapping is informative:
AssuranceLedger ReReview is not a NIST assessment, control implementation, or
compliance determination.

## Evaluate an organization-produced bundle

The `evaluate` command accepts a data-only JSON bundle containing `policy`,
`quorum_report`, `entries`, `checkpoint`, and optional `previous_checkpoint`:

```bash
dspy-security-bench ledger evaluate ledger-bundle.json \
  --evidence-root artifacts/assurance-quorum \
  --evaluation-time 1788048700 \
  --out assurance-ledger.report.json \
  --sarif-out assurance-ledger.sarif \
  --fail-on-trust
```

Python integrations can use `key_descriptor`, `build_policy`,
`make_registration_event`, `make_review_event`, `make_revocation_event`,
`create_checkpoint`, `cosign_checkpoint`, and `analyze_ledger` from
`dspy_security_bench.ledger`. Private keys stay at caller-selected paths; the
protocol neither uploads them nor performs network access.

Production operators should place log and witness keys in separately governed
custody, exchange checkpoints across independent channels, define who may issue
registrations and revocations, retain all historical checkpoints, and establish
an incident process for disputed compromise times. A two-witness demo is not a
universal governance recommendation.

## Who benefits

- **Government programs** can retain review history while detecting whether a
  reviewer credential was retired or compromised, without treating the ledger
  as an ATO.
- **Frontier AI companies** can bind benchmark and evaluator reviews to
  independently observed checkpoints and force retrospective key incidents to
  invalidate affected claims visibly.
- **Cybersecurity companies** can monitor customer-authorized review events and
  countersign checkpoints without becoming the customer's decision authority.
- **Technology partners** can exchange content-addressed review evidence and
  compare checkpoint roots across organizational boundaries.
- **Auditors and the public** can distinguish “signature valid” from “reviewer
  trust current at this evaluation time.”

## Explicit non-claims

AssuranceLedger does not prove identity, employment, reviewer competence,
witness independence, event completeness or truth, continuous log
availability, absence of undisclosed split views, uncompromised key custody,
global consistency, model safety, compliance, certification, ATO, procurement
fitness, deployment approval, or risk acceptance. Witnesses observe a
checkpoint; they do not authorize the system it describes.
