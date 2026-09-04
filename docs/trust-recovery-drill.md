# TrustRecoveryDrill: prove the recovery plan was rehearsed, not just written

Normal AssuranceTrustRoot rotation requires the exact successor to satisfy both
the previous and candidate root thresholds. That fail-closed rule is the point.
If enough old root keys are unavailable or compromised, software must not invent
a silent bypass.

TrustRecoveryDrill addresses a different question:

> Before that crisis happens, can an organization produce bounded evidence that
> its people, roles, evidence, timing, assessment, re-key, independent approval,
> out-of-band distribution, and verification workflow were actually exercised?

It is a content-minimized, deterministic tabletop-evidence protocol. The exact
recovery policy must be authorized by a caller-anchored AssuranceTrustRoot. A
passing drill remains **readiness evidence**, not recovery authority.

When an exercise also needs cryptographic proof that each assigned role key
signed its exact handoff, use the companion
[TrustRecoveryAttestation](trust-recovery-attestation.md) layer. It adds
root-authorized dedicated signer keys, in-toto/DSSE envelopes, unique nonces,
and a preceding-envelope digest chain without granting those keys root authority.

## Why this matters

[NIST SP 800-57 Part 1 Rev. 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5)
describes compromise recovery as a planned process that includes re-keying,
affected-signature identification, damage assessment, designated personnel,
distribution, monitoring, and recovery procedures. It also warns that recovery
availability and key-exposure risk can conflict.

[The Update Framework root-key guidance](https://theupdateframework.github.io/specification/latest/#key-management-and-migration)
states that compromise of a root threshold requires out-of-band recovery and is
extremely difficult to make safe. TrustRecoveryDrill therefore does not pretend
that a tabletop record can replace the old threshold. It helps owners find
preparation gaps while normal authority still exists.

The protocol checks thirteen deterministic conditions:

1. all nine recovery stages are present exactly once;
2. event sequence and timestamps are monotonic;
3. every stage uses an actor assigned to its required role;
4. observed actors satisfy declared separation-of-duty constraints;
5. the organization-diversity floor is met;
6. every stage binds the expected content-free evidence class;
7. the drill binds the exact recovery policy and trust root;
8. no event is future-dated;
9. detection-to-declaration stays within policy;
10. declaration-to-replacement preparation stays within policy;
11. replacement-to-out-of-band-distribution rehearsal stays within policy;
12. distribution-to-independent-verification stays within policy; and
13. the completed drill remains within the policy's freshness window.

## What enters the report

The drill record contains no incident narrative, alert body, key bytes,
replacement root, distribution address, communication transcript, or recovery
instruction. Each event carries only:

- a sequence and Unix timestamp;
- a fixed event type and fixed evidence class;
- owner-declared actor and organization identifiers; and
- a SHA-256 digest of the retained evidence.

The expected stages are:

| Stage | Required role | Evidence class |
|---|---|---|
| `compromise-detected` | incident commander | alert record |
| `incident-declared` | incident commander | incident declaration |
| `affected-signatures-inventoried` | auditor | signature inventory |
| `damage-assessment-completed` | auditor | damage assessment |
| `replacement-root-prepared` | key custodian | replacement-root manifest |
| `independent-approval-recorded` | independent approver | approval record |
| `out-of-band-distribution-rehearsed` | distributor | distribution rehearsal |
| `replacement-verification-completed` | auditor | verification record |
| `lessons-retained` | incident commander | lessons record |

`content_fields_processed: 0`, `replacement_roots_activated: 0`, and
`automatic_actions: 0` are report invariants.

## Five-minute fictional proof

```bash
uv sync --locked --extra dev --extra signing

dspy-security-bench ledger demo --out-dir artifacts/assurance-ledger

dspy-security-bench ledger verify-recovery-drill \
  artifacts/assurance-ledger/trust-recovery-drill.report.json
```

The demo emits:

- `trust-recovery-policy.json` — five exact role assignments, mandatory
  custodian/approver separation, three-organization diversity, and response
  windows;
- `trust-recovery-drill.json` — nine simulation-only, content-minimized stage
  records bound to TrustRoot v3;
- `trust-recovery-drill.report.json` — thirteen passing checks and exact nested
  TrustRoot authorization evidence; and
- `trust-recovery-drill.sarif` — an empty result set for the valid fixture.

Every organization, person, root, event, and evidence digest in the demo is
fictional. No real key is recovered or changed.

## Author an organization-owned policy

Use `build_recovery_policy` from the Python API or create JSON matching
`assuranceledger-trust-recovery-policy.schema.json`. The policy declares:

- its plan ID, trust domain, root version, and validity window;
- one or more actors for each of `incident-commander`, `key-custodian`,
  `independent-approver`, `distributor`, and `auditor`;
- explicit role pairs that must use different actors;
- a minimum number of distinct organizations; and
- maximum seconds for the four response segments and completed-drill age.

The key custodian and independent approver must always be a separated pair.
Additional separation constraints remain owner-controlled. Actors are accepted
only when both the actor and organization match the policy assignment.

Authorize the exact `policy_sha256` in an AssuranceTrustRoot as policy type
`dspy-security-bench-assurance-trust-recovery-policy`. A policy with the same
friendly plan ID but different role, timing, or organization bytes does not
inherit authority.

## Record a simulation-only drill

Use `recovery_event` and `build_recovery_drill` from the Python API. These
builders select the fixed evidence class for each event, sort by sequence, bind
the exact root/policy, enforce `simulation_only: true`, and compute the drill
digest. Retain the referenced evidence under the organization's incident,
privacy, records, and access-control policies; only its digest enters this
portable report.

Evaluate and independently recompute:

```bash
dspy-security-bench ledger evaluate-recovery-drill \
  trust-recovery-policy.json \
  trust-recovery-drill.json \
  trust-root-v3.json \
  --expected-root-sha256 "$INDEPENDENTLY_TRUSTED_ROOT_V3_SHA256" \
  --evaluation-time 1819680700 \
  --out trust-recovery-drill.report.json \
  --sarif-out trust-recovery-drill.sarif \
  --fail-on-readiness

dspy-security-bench ledger verify-recovery-drill \
  trust-recovery-drill.report.json
```

The evaluation embeds the exact inputs and nested TrustRoot report. The verifier
recomputes all authorization, timing, role, separation, diversity, binding, and
freshness outcomes offline.

## Outcomes remain non-overlapping

| Status | Exact meaning |
|---|---|
| `recovery_readiness_evidenced` | All thirteen checks pass under an active exact policy authorized by the caller-anchored root. |
| `recovery_readiness_not_evidenced` | The policy/root are usable, but one or more drill checks fail. |
| `invalid_recovery_evidence` | Policy or drill structure, digest, identifiers, or bounds are invalid. |
| `untrusted_root` | The root is not currently valid against the caller's exact trust anchor. |
| `recovery_policy_not_authorized` | The current root does not authorize the exact recovery-policy digest. |
| `inactive_recovery_policy` | Evaluation is outside the policy's signed validity window. |
| `stale_recovery_drill` | The exercise is older than the policy's maximum age. |

SARIF emits one stable `TRD001`–`TRD013` rule per failed check plus explicit
rules for invalid source evidence, untrusted roots, unauthorized policies, and
inactive policies. It never remediates a finding.

## Security and adoption boundary

A green report does not prove that:

- the underlying retained records are truthful or sufficient;
- named actors or organizations have externally proofed identities;
- people, HSMs, backups, communication paths, or facilities will be available;
- compromised signatures have all been found;
- the replacement root is safe, approved, distributed, installed, or current;
- an out-of-band recovery mechanism is itself secure; or
- any compliance, procurement, incident-reporting, ATO, or risk decision is
  satisfied.

Use the report as a tabletop finding input. Keep real recovery authority in the
organization's approved incident, key-management, configuration-control, and
authorization processes. Never weaken the normal dual-threshold rotation path
merely to make a drill pass.
