# RootViewQuorum: detect stale or split trust-root distribution

RootViewQuorum turns a question that is usually answered informally—“did our
independent distribution paths receive the same trust root?”—into portable,
offline-verifiable evidence.

An owner pins a policy of Ed25519 observer keys and declared organizations.
Each observer signs a fresh challenge that binds both the verifier's exact
candidate-root digest and the exact root object the observer received. The
analyzer then distinguishes four views:

| View | Meaning | Effect |
|---|---|---|
| `matching` | exact candidate version and digest | counts toward quorum |
| `lagging` | lower root version | reported, but never counts as agreement |
| `same_version_conflict` | same version, different digest | blocks acceptance even when outvoted |
| `newer` | version above the candidate | blocks acceptance even when outvoted |

This addresses the distributor-withholding boundary left explicit by
AssuranceTrustRootChain. It is useful when agencies, critical-infrastructure
operators, model providers, software vendors, auditors, and industry
information-sharing groups obtain root metadata through separately governed
paths and need evidence of what those paths returned.

## Security model

```text
owner-retained policy SHA-256                  verifier-generated nonce
              │                                          │
              └────────────────┬─────────────────────────┘
                               ▼
                      candidate root SHA-256
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
       observer A         observer B         observer C
       organization A     organization B     organization C
             │                 │                 │
             └──── Ed25519-signed exact observed roots ────┘
                               │
                               ▼
                     deterministic offline checks
                               │
           matching quorum / lag / conflict / newer view
```

The policy pin and nonce are deliberate. A policy supplied only beside its own
receipts could replace the trusted observer set. A reused nonce could turn an
old observation into apparent evidence for a new request. Operators should
generate an unpredictable nonce per decision and retain both it and the policy
digest outside the response channel.

Same-version conflicts and higher-version views are non-outvotable. Majority
agreement is not allowed to erase evidence that one authorized observer saw a
different root for the same version or a root newer than the verifier's
candidate.

## Five-minute demonstration

The complete fictional AssuranceLedger demo includes three independent
root-view observations:

```bash
uv sync --locked --extra dev --extra signing

dspy-security-bench ledger demo --out-dir artifacts/assuranceledger

dspy-security-bench ledger verify-root-view \
  artifacts/assuranceledger/root-view.report.json
```

Inspect these files:

- `root-view-policy.json`;
- three `root-view-*.receipt.json` observations;
- `root-view.report.json`; and
- `root-view.sarif`.

The demo is fictional protocol evidence. It is not a finding about any real
agency, organization, distribution network, root, or product.

## Create an independently pinned policy

Describe each observer's public key. Private keys remain with the observers.

```bash
dspy-security-bench ledger describe-root-view-observer \
  observer-a.public.pem \
  --observer-id observer-a \
  --organization-id organization-a \
  --out observer-a.json
```

Create a JSON spec containing the descriptors:

```json
{
  "quorum_id": "production-root-distribution",
  "trust_domain": "example-ai-assurance",
  "observers": [
    {"entity_id": "observer-a", "organization_id": "organization-a", "public_key_spki_base64": "...", "public_key_sha256": "..."},
    {"entity_id": "observer-b", "organization_id": "organization-b", "public_key_spki_base64": "...", "public_key_sha256": "..."},
    {"entity_id": "observer-c", "organization_id": "organization-c", "public_key_spki_base64": "...", "public_key_sha256": "..."}
  ],
  "minimum_observers": 2,
  "minimum_distinct_organizations": 2
}
```

Then build and independently retain the exact policy and its digest:

```bash
dspy-security-bench ledger create-root-view-policy \
  root-view-policy-spec.json \
  --out root-view-policy.json
```

Policy identifiers and organization assignments are accountable owner
assertions. The software does not prove legal identity, governance
independence, or private-key custody.

## Issue observations

The verifier first selects a candidate root and creates a fresh nonce. Each
observer signs its own exact observed root while binding that challenge:

```bash
dspy-security-bench ledger sign-root-view \
  root-view-policy.json \
  observer-a.private.pem \
  observer-a-observed-root.json \
  --observer-id observer-a \
  --candidate-root-sha256 "$CANDIDATE_ROOT_SHA256" \
  --request-nonce "$FRESH_ROOT_VIEW_NONCE" \
  --out observer-a.root-view.json
```

The signed statement contains no model prompt, evaluation content, review
content, or credential. It does embed the complete observed public trust-root
object so an offline verifier can recompute the digest, validate the current
root threshold, and classify the view without trusting a label.

## Evaluate and reverify

```bash
dspy-security-bench ledger evaluate-root-view \
  root-view-policy.json candidate-root.json \
  observer-a.root-view.json \
  observer-b.root-view.json \
  observer-c.root-view.json \
  --expected-policy-sha256 "$PINNED_ROOT_VIEW_POLICY_SHA256" \
  --request-nonce "$FRESH_ROOT_VIEW_NONCE" \
  --out root-view.report.json \
  --sarif-out root-view.sarif \
  --fail-on-view

dspy-security-bench ledger verify-root-view root-view.report.json \
  --expected-policy-sha256 "$PINNED_ROOT_VIEW_POLICY_SHA256" \
  --candidate-root-sha256 "$CANDIDATE_ROOT_SHA256" \
  --request-nonce "$FRESH_ROOT_VIEW_NONCE"
```

Ten deterministic checks cover policy pinning and integrity, candidate-root
integrity/domain, exact receipt shape, candidate and nonce binding, observer
identity/organization/key/signature, embedded-root recomputation, unique
matching-observer threshold, matching-organization threshold, and conflicting
or newer roots.

The report and every source receipt can be validated with the three shipped
Draft 2020-12 schemas. Reverification rebuilds the complete report from the
embedded policy, candidate root, and receipts. Replacing the outer SHA-256 after
changing a count, signature, or classification does not pass.

## Cross-language known-answer vectors

The committed [`interop/root-view-quorum-v1`](../interop/root-view-quorum-v1/README.md)
pack lets another language or product test the protocol without invoking the
Python generator. It contains 21 byte-stable public input/report artifacts plus
one immutable manifest and eight ordered cases:

| Case | Required decision |
|---|---|
| `matching-quorum` | accept `root_view_corroborated` |
| `lagging-view-preserved` | accept while retaining the lagging observation |
| `same-version-conflict` | accept the report with `same_version_root_conflict` |
| `newer-root-reported` | accept the report with `newer_root_reported` |
| `duplicate-observer` | accept the fail-closed `insufficient_root_observers` report |
| `nonce-mismatch` | accept the fail-closed `root_view_request_mismatch` report |
| `invalid-observer-signature` | accept the fail-closed `invalid_root_view_evidence` report |
| `rehashed-summary-tamper` | reject the report even though its outer digest was recomputed |

```bash
# Verify exact file bytes, the immutable manifest identity, and all outcomes.
dspy-security-bench ledger verify-root-view-vectors \
  interop/root-view-quorum-v1

# Recreate the official pack byte-for-byte in a new directory.
dspy-security-bench ledger generate-root-view-vectors \
  --out-dir /tmp/root-view-quorum-v1

# Execute the same cases through the independent zero-dependency implementation.
node interop/root-view-quorum-node/verify.mjs \
  interop/root-view-quorum-v1

# Independently reverify one report with machine-readable output.
node interop/root-view-quorum-node/verify.mjs \
  --report root-view.report.json
```

Protocol digests use SHA-256 over UTF-8 JSON with recursively sorted object
keys, no insignificant whitespace, direct Unicode emission, and rejection of
non-finite numbers. Corpus files use sorted keys, two-space indentation, and
one LF terminator. This is the project's defined canonical form for this pack,
not a claim of RFC 8785 compatibility.

The manifest binds every file SHA-256, case input, expected semantic outcome,
and verifier-acceptance decision. Its expected digest is compiled into the v1
verifier, so changing and rehashing the manifest cannot impersonate the
official corpus. The generator derives intentionally public, test-only Ed25519
seeds inside a temporary directory and emits no private key file.

The Node.js 18+ runner is deliberately separate from the package and never
imports or invokes Python. Using only built-in filesystem and cryptography
APIs, it independently validates the immutable manifest, exact file set,
canonical digests, Ed25519 key identities and signatures, root thresholds,
observer bindings, classifications, quorums, report summaries, and required
tamper rejection. It verifies Ed25519, ECDSA P-256/SHA-256, and RSA-PSS/SHA-256
trust-root signatures; observer receipts remain Ed25519. A 21-case differential
suite rehashes mutations to every summary field, findings, receipt results,
metadata, limitations, and a receipt signature and requires both Python and
Node to reject them. It is not a published npm SDK.

The structure follows the practical pattern used by the
[TUF conformance suite](https://github.com/theupdateframework/tuf-conformance)
and [Sigstore conformance suite](https://github.com/sigstore/sigstore-conformance),
while deterministic signature inputs follow the known-answer testing principle
illustrated by [RFC 8032 test vectors](https://www.rfc-editor.org/rfc/rfc8032.html#section-7).
Passing these eight cases is a finite interoperability signal only. It is not
general conformance, fuzzing, NIST ACVP/CAVP or FIPS validation, implementation
certification, government endorsement, deployment approval, or an ATO.

## Deployment guidance

- Keep the observer-policy pin and challenge nonce in a verifier-owned trust
  boundary, not solely in the response bundle.
- Separate observer keys and operational administration across organizations
  and failure domains; distinct strings alone do not create independence.
- Obtain views through distribution paths whose failure modes are meaningfully
  different for the deployment.
- Treat `same_version_root_conflict` as evidence requiring investigation. The
  analyzer does not choose a truthful side or infer compromise or intent.
- Treat `newer_root_reported` as a signal to retrieve and validate the complete
  successor chain. A receipt alone does not prove continuity from the candidate.
- Treat lagging observations as distribution telemetry, not votes for the
  candidate.
- Combine the result with TrustRootChain for cryptographic continuity and
  TrustRootTimeGate for validity across signed time uncertainty.

## Exact claim boundary

A passing `root_view_corroborated` result means only that the supplied,
policy-authorized observers—meeting the configured identity and declared-
organization thresholds—signed the exact candidate root for this exact nonce,
and that none of the supplied valid observations contains a same-version
conflict or higher version.

It does **not** prove global freshness, complete dissemination, legal identity,
operational independence, absence of a partition outside the selected
observers, root continuity, correctness of the root's authorized policies,
compliance, certification, government endorsement, authorization to operate,
or approval to install a root. It performs zero network requests, root
installations, notifications, revocations, deployments, or automatic actions.

## Design references

The design follows security lessons from these primary sources without claiming
wire compatibility or conformance:

- [The Update Framework specification](https://theupdateframework.github.io/specification/latest/) describes sequential root updates and the freeze risk when an attacker withholds newer metadata.
- [C2SP transparency-log witness protocol](https://c2sp.org/tlog-witness) describes witnesses retaining checkpoints and cosigning only consistent advancement.
- [IETF Key Transparency Architecture](https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/) discusses monitoring, split views, third-party participation, and gossip assumptions.
- [TUF conformance](https://github.com/theupdateframework/tuf-conformance) and [Sigstore conformance](https://github.com/sigstore/sigstore-conformance) demonstrate cross-implementation test-suite patterns.
- [RFC 8032 test vectors](https://www.rfc-editor.org/rfc/rfc8032.html#section-7) provide deterministic known-answer examples for Ed25519.

RootViewQuorum is not TUF, a C2SP witness protocol, Key Transparency, SCITT,
PKI, a trust store, a root installer, or a software-update client.
