# TrustRecoveryAttestation v1

`TrustRecoveryAttestation` turns each content-minimized `TrustRecoveryDrill`
handoff into an independently verifiable, role-scoped signature. It is designed
for agencies, critical-infrastructure operators, AI labs, vendors, assessors,
and incident-response partners that need to answer a narrower question than
“did the tabletop pass?”:

> Did the policy-authorized actor for every recovery role sign the exact event,
> in order, under an exact policy authorized by the caller-pinned trust root?

The answer is still **evidence, not recovery authority**. The implementation
does not replace, revoke, distribute, install, or activate a root.

## Why this layer exists

The recovery-drill protocol deliberately treats actor and organization labels
as owner assertions. That keeps the first layer portable, but a copied JSON
record could otherwise claim that an auditor or independent approver performed
a handoff.

TrustRecoveryAttestation closes that integrity gap with three composable
mechanisms:

1. an exact signer policy is authorized by `AssuranceTrustRoot`;
2. each event becomes an [in-toto Statement
   v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
   inside a [DSSE
   envelope](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md);
3. every statement includes a unique nonce and the digest of the preceding
   envelope, creating one ordered handoff chain.

This design follows the in-toto model of authenticating what step was
performed, by whom, and in what order. It also supports the preparation,
authorization, integrity verification, and documentation goals described by
[NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final). It does
not claim conformance to a government profile or registration as a standard
in-toto predicate.

## Security model

```text
caller-pinned root digest
          │
          ▼
AssuranceTrustRoot ── authorizes exact recovery policy digest
          │           and exact attester-policy digest
          ▼
recovery event 0 ── DSSE signature ── previous = 000…000
          │
          ▼ sha256(envelope 0)
recovery event 1 ── DSSE signature ── previous = digest(envelope 0)
          │
         ...
          ▼ sha256(envelope 7)
recovery event 8 ── DSSE signature ── terminal chain digest
```

The attester policy embeds dedicated Ed25519 public keys. Recovery-event keys
do not need to be operational root-signing keys, which lets adopters isolate
tabletop and incident evidence from root authority. The trust root authorizes
the **policy digest**, not individual runtime actions.

Every DSSE payload signs the standard DSSE pre-authentication encoding (PAE),
including the payload type. The authenticated in-toto predicate binds:

- the exact event subject digest, sequence, type, evidence digest, and time;
- the exact recovery policy and recovery-attestation policy digests;
- the plan, drill, trust domain, root digest, and root version;
- signer, recovery role, organization, and public-key digest;
- issuance time, unique nonce, preceding envelope digest, and
  `simulation_only=true`;
- the protocol's non-authorizing claim boundary.

## Ten deterministic checks

| Rule | Pass condition |
|---|---|
| `TRA001` | All nine recovery events have exactly one ordered attestation |
| `TRA002` | Every DSSE envelope and in-toto Statement has the frozen shape and canonical payload |
| `TRA003` | Every subject and predicate binds the exact event |
| `TRA004` | Every predicate binds the exact root, policies, plan, and drill |
| `TRA005` | Every signer matches the event actor, organization, and assigned recovery role |
| `TRA006` | Every DSSE Ed25519 signature verifies under the authorized key |
| `TRA007` | Event, signature, evaluation, and policy times are correctly ordered |
| `TRA008` | Every handoff nonce is valid and unique within the chain |
| `TRA009` | The preceding-envelope links form one exact digest chain |
| `TRA010` | The caller-anchored trust root authorizes both exact policy digests |

No failed check is averaged away. A missing signature, replayed nonce, broken
link, wrong role, changed event, changed policy, or changed root yields a
non-passing result.

## Run the reference chain

Generate the fictional, local-only demonstration:

```bash
dspy-security-bench ledger demo --out-dir artifacts/assurance-ledger
```

The demo writes:

```text
trust-recovery-attestation-policy.json
trust-recovery-attestations/
├── event-00.json
├── event-01.json
├── ...
└── event-08.json
trust-recovery-attestations.report.json
trust-recovery-attestations.sarif
```

Recompute the saved report, including every embedded signature and source
artifact:

```bash
dspy-security-bench ledger verify-recovery-attestations \
  artifacts/assurance-ledger/trust-recovery-attestations.report.json
```

## Build a signer record

Create a dedicated Ed25519 key through your approved key-management process,
then describe only its public half:

```bash
dspy-security-bench ledger describe-recovery-attester \
  incident-commander.public.pem \
  --signer-id incident-commander-one \
  --recovery-role incident-commander \
  --organization-id agency-program \
  --out incident-commander.attester.json
```

Combine one or more assigned signers for each of the five recovery roles into
an attestation policy with `build_attestation_policy(...)`. The policy validity
window must fit inside the recovery-policy window, and every signer must match
an exact role assignment. Add both policy descriptors to the trust root before
threshold signing that root.

## Sign one handoff

The first event uses the all-zero genesis digest:

```bash
dspy-security-bench ledger sign-recovery-event \
  recovery-attestation-policy.json \
  recovery-policy.json \
  recovery-drill.json \
  incident-commander.private.pem \
  --event-index 0 \
  --issued-at 1800000005 \
  --nonce exercise-2026q3-handoff-1 \
  --out event-00.json
```

For each later event, pass the SHA-256 digest of the complete preceding
envelope:

```bash
dspy-security-bench ledger sign-recovery-event \
  recovery-attestation-policy.json recovery-policy.json recovery-drill.json \
  next-role.private.pem \
  --event-index 1 \
  --issued-at 1800000065 \
  --nonce exercise-2026q3-handoff-2 \
  --previous-attestation-sha256 "$PREVIOUS_ENVELOPE_SHA256" \
  --out event-01.json
```

The CLI never generates a nonce implicitly. Operators must supply an identifier
from their approved exercise process so retries and accidental reuse remain
observable.

## Evaluate the full chain

```bash
dspy-security-bench ledger evaluate-recovery-attestations \
  recovery-attestation-policy.json \
  recovery-policy.json \
  recovery-drill.json \
  trust-root.json \
  event-00.json event-01.json event-02.json event-03.json event-04.json \
  event-05.json event-06.json event-07.json event-08.json \
  --expected-root-sha256 "$PINNED_ROOT_SHA256" \
  --evaluation-time 1800000700 \
  --out recovery-attestations.report.json \
  --sarif-out recovery-attestations.sarif \
  --fail-on-authentication
```

The expected passing status is `authenticated_recovery_handoffs`. The report
embeds every input required for later offline recomputation.

## What a passing report means

A pass establishes that, for the supplied simulation and caller-selected trust
anchor:

- each exact recovery event was signed by its policy-authorized actor key;
- signer roles and organizations match the root-authorized recovery plan;
- the chain is complete, ordered, non-replayed within the supplied drill, and
  cryptographically bound end to end;
- the underlying recovery-readiness report also passes; and
- the analyzer took zero actions and processed zero evidence-content fields.

A pass does **not** establish legal identity, signer competence, organization
independence, safe private-key custody, underlying record truth, successful
real-world recovery, regulatory compliance, an authorization to operate, or
risk acceptance. If a signing key is compromised, its signatures can be
forged; key protection, revocation, and external identity proofing remain
deployment responsibilities.

## Integration guidance

- Store attester private keys outside the drill bundle and separate them from
  root-signing keys.
- Pin `root_sha256` through an independent channel; do not learn it from the
  report being verified.
- Treat organization and role labels as governed identifiers, not verified
  corporate or personal identity.
- Keep evidence digests high entropy. Do not hash short secrets or sensitive
  labels that are practical to guess offline.
- Preserve the nine envelopes in order. The terminal envelope digest is a
  compact comparison point for independent observers.
- Upload SARIF for review and alerting, but keep incident decisions and root
  operations in the accountable external workflow.
