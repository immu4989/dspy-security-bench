# AssuranceTrustRoot: rotate trust without silently replacing it

AssuranceLedger can prove that a reviewer key was registered, later retired,
or retrospectively compromised. AssuranceTrustRoot answers the prior question:

> Which keys and exact policies is this verifier allowed to trust, and how can
> that authority change without a repository, mirror, or single new key silently
> replacing it?

The protocol is an offline, self-contained trust-anchor continuity artifact for
AssuranceLedger, ObserverReceipt, and AssuranceQuorum deployments. It provides:

- an independently pinned first-root digest;
- threshold signatures from distinct declared organizations;
- exact successor versions and predecessor-digest linkage;
- authorization by both the old root threshold and the new root threshold;
- explicit expiration that exposes possible freeze or neglected rotation;
- exact authorized policy digests rather than name-only policy selection;
- algorithm-explicit keys using Ed25519, ECDSA P-256/SHA-256, or RSA-PSS/SHA-256;
- a strict Draft 2020-12 artifact schema and report schema;
- deterministic offline report recomputation and SARIF; and
- zero automatic key, policy, deployment, notification, ATO, or risk action.

It is purpose-built for the AssuranceLedger evidence plane. It borrows the
dual-threshold root-rotation security property from The Update Framework, but it
is **not** a TUF repository, wire format, client updater, SCITT transparency
service, PKI, certificate system, or operating-system trust store.

## Why this matters

A self-signed JSON file is not a trust anchor. An attacker who can replace both
the file and its keys can produce a perfectly valid self-signature. The first
AssuranceTrustRoot is therefore accepted only when the caller supplies its exact
`root_sha256` through an independently governed bootstrap process.

Later roots have a stronger continuity requirement. Root `N+1` must:

1. name version `N+1`, not an older version or a skipped version;
2. bind the exact full digest of root `N`;
3. satisfy the root threshold declared by root `N`; and
4. satisfy the root threshold declared by root `N+1`.

The two thresholds permit planned rotation, including complete replacement of
the root key set, while preventing either a minority of old keys or a minority
of new keys from unilaterally changing trust. Duplicate signatures never
increase a threshold. A separately declared minimum number of organizations
also prevents two keys assigned to one organization from satisfying a two-
organization policy.

This design is informed by:

- [The Update Framework root-update workflow](https://theupdateframework.github.io/specification/latest/#update-root),
  which requires sequential versions and authorization under both current and
  candidate root thresholds;
- [NIST CSWP 39upd1, Considerations for Achieving Crypto Agility](https://doi.org/10.6028/NIST.CSWP.39-upd1),
  which emphasizes explicit algorithm identification and planned transitions;
  and
- [RFC 9943, the SCITT architecture](https://www.rfc-editor.org/rfc/rfc9943.html),
  which treats trust anchors and registration policy as explicit transparency-
  service inputs.

The implementation does not claim conformance to those broader systems.

## Five-minute fictional proof

The existing AssuranceLedger demo now writes a two-root transition. All private
keys are generated in a temporary directory and discarded:

```bash
uv sync --locked --extra dev --extra signing

dspy-security-bench ledger demo --out-dir artifacts/assurance-ledger

dspy-security-bench ledger verify-trust-root \
  artifacts/assurance-ledger/trust-root.report.json
```

Inspect:

- `trust-root-v1.json` — the previously trusted two-organization root;
- `trust-root-v2.json` — an exact successor signed under both old and new root
  thresholds;
- `trust-root.report.json` — the fully recomputable `trusted_rotation` result;
  and
- `trust-root.sarif` — an empty result set for the valid reference transition.

The roots authorize the exact fictional ledger, observer, and quorum policy
digests created by the demo. They are protocol fixtures, not keys or approvals
for any real organization or government system.

## Create an organization-owned root

First convert each PEM public key into the algorithm-explicit descriptor used by
the root format:

```bash
dspy-security-bench ledger describe-trust-key root-a.public.pem \
  --entity-id root-a \
  --organization-id agency-program-office \
  --out root-a.key.json
```

The descriptor includes only public material: entity and organization labels,
the detected signature scheme, DER SubjectPublicKeyInfo encoded as base64, and
its SHA-256 key identifier. Supported schemes are:

| Scheme identifier | Accepted key |
|---|---|
| `ed25519` | Ed25519 |
| `ecdsa-sha2-nistp256` | ECDSA on NIST P-256 with SHA-256 |
| `rsassa-pss-sha256` | RSA-PSS with SHA-256 and an RSA key of at least 2048 bits |

An organization owns the algorithm choice and any FIPS, HSM, key-generation,
custody, or migration requirement. These three software-verifiable schemes are
not post-quantum signatures.

Prepare a data-only spec with exactly these fields:

```json
{
  "trust_domain": "example-ai-assurance",
  "version": 1,
  "issued_at": 1788048000,
  "expires_at": 1819584000,
  "keys": ["replace with complete key descriptor objects"],
  "roles": {
    "ledger-observer": {
      "keyids": ["sha256"],
      "signature_threshold": 1,
      "minimum_distinct_organizations": 1
    },
    "ledger-operator": {
      "keyids": ["sha256"],
      "signature_threshold": 1,
      "minimum_distinct_organizations": 1
    },
    "ledger-witness": {
      "keyids": ["sha256-a", "sha256-b"],
      "signature_threshold": 2,
      "minimum_distinct_organizations": 2
    },
    "quorum-reviewer": {
      "keyids": ["sha256"],
      "signature_threshold": 1,
      "minimum_distinct_organizations": 1
    },
    "root": {
      "keyids": ["sha256-a", "sha256-b"],
      "signature_threshold": 2,
      "minimum_distinct_organizations": 2
    }
  },
  "authorized_policies": [
    {
      "policy_type": "dspy-security-bench-assurance-ledger-policy",
      "policy_sha256": "replace-with-the-exact-policy-digest"
    }
  ]
}
```

Every role must be present even when one deployment reuses a key between
roles. The tool rejects unknown keys, duplicate key or entity identifiers,
impossible signature or organization thresholds, unsorted/duplicate policy
records, unsupported policy types, weak RSA keys, and mismatched algorithm
labels.

Sign the first root with enough root-role private keys to satisfy both its key
and organization thresholds:

```bash
dspy-security-bench ledger create-trust-root root-v1.spec.json \
  --private-key root-a.private.pem \
  --private-key root-b.private.pem \
  --out root-v1.json
```

Private-key files are read locally and never embedded. The CLI does not create,
upload, escrow, delete, or rotate them.

## Bootstrap explicitly

Move the first root digest through an independently reviewed channel, then pin
that exact lowercase SHA-256 value during evaluation:

```bash
dspy-security-bench ledger evaluate-trust-root root-v1.json \
  --expected-root-sha256 "$REVIEWED_ROOT_SHA256" \
  --expected-domain example-ai-assurance \
  --minimum-version 1 \
  --evaluation-time 1788048100 \
  --policy ledger-policy.json \
  --policy observer-policy.json \
  --out trust-root-bootstrap.report.json \
  --sarif-out trust-root-bootstrap.sarif \
  --fail-on-trust
```

Without `--expected-root-sha256` or `--trusted-root`, an otherwise valid first
root is `untrusted_bootstrap`. Self-signature alone is never silently treated as
external trust.

## Rotate with both thresholds

Prepare version 2 with the candidate keys and roles. `create-trust-root` derives
`previous_root_sha256` from the supplied old root. Current-root private keys
sign the candidate role; predecessor private keys sign the same exact candidate
payload under the old role:

```bash
dspy-security-bench ledger create-trust-root root-v2.spec.json \
  --previous-root root-v1.json \
  --private-key new-root-a.private.pem \
  --private-key new-root-b.private.pem \
  --previous-private-key old-root-a.private.pem \
  --previous-private-key old-root-b.private.pem \
  --out root-v2.json

dspy-security-bench ledger evaluate-trust-root root-v2.json \
  --trusted-root root-v1.json \
  --expected-domain example-ai-assurance \
  --minimum-version 2 \
  --evaluation-time 1788134500 \
  --policy ledger-policy.json \
  --out trust-root-rotation.report.json \
  --sarif-out trust-root-rotation.sarif \
  --fail-on-trust

dspy-security-bench ledger verify-trust-root \
  trust-root-rotation.report.json
```

The report embeds both public roots, every policy input, the anchor parameters,
threshold counts, exact algorithm-set transition, errors, limitations, and
final digest. Verification is standalone and performs no network request.

## Outcomes do not collapse

| Status | Exact meaning |
|---|---|
| `trusted_bootstrap` | The valid, unexpired first root exactly matches the independently supplied digest. |
| `trusted_rotation` | The valid, unexpired exact successor is authorized by both old and new thresholds. |
| `untrusted_bootstrap` | No prior root or independently pinned digest was supplied. |
| `invalid_trust_evidence` | Structure, key material, signatures, or self-threshold verification failed. |
| `expired_trust_root` | The candidate expired at or before the evaluation time. This exposes a possible freeze; it does not infer cause. |
| `rollback_detected` | The candidate does not advance trusted state or is below the caller's version floor. |
| `version_gap_detected` | The candidate skipped an intermediate version, so continuity cannot be reconstructed. |
| `trust_discontinuity` | Domain, predecessor digest, old threshold, or another continuity condition failed. |
| `policy_not_authorized` | At least one exact policy input is invalid or absent from the signed allowlist. |

Status precedence is fail-closed: malformed or cryptographically invalid source
evidence cannot be relabeled as a version or authorization issue. Expiration is
not treated as a fresh root, and a policy with the same friendly name but
different bytes does not inherit authorization.

## Security boundary

AssuranceTrustRoot does **not**:

- decide who should control a root key or whether organizations are independent;
- prove private keys were generated or stored securely;
- discover a compromise, fetch a newer root, or distinguish withholding from an
  operator who simply failed to rotate;
- make Ed25519 acceptable in a deployment that requires an approved algorithm;
- turn an authorized policy into a safe, complete, compliant, or approved one;
- certify a product, approve procurement, issue an ATO, deploy a system, revoke
  a credential, notify an incident recipient, or accept risk.

The deployment owner must independently distribute the first digest, persist
the last trusted root and minimum version, protect signing keys, review role and
organization assignments, set an operationally meaningful expiration, retain
every intermediate root, and define recovery when an old threshold can no
longer sign a successor.
