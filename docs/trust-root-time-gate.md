# TrustRootTimeGate

TrustRootTimeGate turns independently signed bounded-time evidence into a
fail-closed trust-root decision. It composes two existing AssuranceLedger
surfaces without inventing a hidden clock:

1. `AssuranceTimeQuorum` proves that separately authorized source keys signed
   overlapping uncertainty intervals for one root digest and one fresh nonce.
2. `AssuranceTrustRoot` verifies the candidate at both ends of that
   conservative interval.

The result is `temporally_trusted_root` only when the root is trusted throughout
the complete interval.

```text
signed time-source receipts                     candidate root
 [997,1003] [999,1005] [999,1003]                    │
             │                                       │
             └── conservative overlap [999,1003] ────┤
                                                     │
                              evaluate at 999 ───────┤ trusted
                              evaluate at 1003 ──────┤ trusted
                                                     ▼
                                          temporally_trusted_root
```

## The boundary failure this closes

A single best-estimate timestamp can hide uncertainty around security
boundaries. If a root expires at Unix time `1002`, choosing the midpoint `1001`
would accept it even though the supported interval extends to `1003`.
TrustRootTimeGate rejects that case as `root_expires_within_interval`.

The same rule applies at issuance: a root issued at `1000` cannot be treated as
trusted across `[999, 1003]`. It fails as
`root_not_yet_valid_for_interval`.

Checking both endpoints is sound for the root evaluator's monotonic temporal
predicates:

```text
issued_at <= evaluation_time < expires_at
```

It is not a general proof technique for arbitrary time-dependent policy logic.

## Eight deterministic checks

| Rule | Requirement |
|---|---|
| `ART001` | The complete embedded TimeQuorum report recomputes exactly |
| `ART002` | Its policy digest matches the caller-retained pin |
| `ART003` | Its request nonce matches the caller-retained challenge |
| `ART004` | Its signed subject is the exact candidate-root digest |
| `ART005` | The independent bounded-time quorum passed |
| `ART006` | A non-negative ordered conservative interval exists |
| `ART007` | The root is trusted at the lower endpoint |
| `ART008` | The root is trusted at the upper endpoint |

The gate preserves distinct outcomes for invalid evidence, policy replacement,
nonce replay, subject rebinding, unavailable time, not-yet-valid authority,
expiration within uncertainty, and non-temporal root-trust failures.

## Try the complete fictional fixture

```bash
dspy-security-bench ledger demo --out-dir artifacts/assuranceledger

dspy-security-bench ledger verify-trust-root-time \
  artifacts/assuranceledger/trust-root-time.report.json
```

The demo report binds root v3, its previously trusted v2 predecessor, two exact
root-authorized policy inputs, the three-source TimeQuorum report, both endpoint
root evaluations, eight findings, and the zero-action boundary. It also emits
`trust-root-time.sarif` and includes a rehashed semantic mutation in
VerifierConformance v8.

## Evaluate a deployment-owned rotation

First create and verify bounded-time evidence whose `subject_sha256` is exactly
the candidate root's `root_sha256`. Retain the policy digest and fresh request
nonce outside the returned report. Then run:

```bash
dspy-security-bench ledger evaluate-trust-root-time \
  candidate-root.json time-quorum.report.json \
  --trusted-root previously-trusted-root.json \
  --expected-time-policy-sha256 "$PINNED_TIME_POLICY_SHA256" \
  --expected-request-nonce "$RETAINED_FRESH_NONCE" \
  --expected-domain "$TRUST_DOMAIN" \
  --minimum-version 3 \
  --policy trust-recovery-policy.json \
  --policy trust-recovery-attestation-policy.json \
  --out trust-root-time.report.json \
  --sarif-out trust-root-time.sarif \
  --fail-on-trust
```

For an initial bootstrap, replace `--trusted-root` with an independently
distributed `--expected-root-sha256`. Those options are mutually exclusive.

Recompute the saved decision offline and repeat the two retained expectations:

```bash
dspy-security-bench ledger verify-trust-root-time \
  trust-root-time.report.json \
  --expected-time-policy-sha256 "$PINNED_TIME_POLICY_SHA256" \
  --expected-request-nonce "$RETAINED_FRESH_NONCE"
```

The second command detects any change to the nested time report, candidate or
predecessor root, authorized policies, endpoint evaluations, findings, summary,
or outer digest.

## Safe deployment pattern

- Generate a new unpredictable nonce for every acceptance decision and retain
  it with the request context.
- Distribute the TimeQuorum policy pin and bootstrap root digest through
  independently governed channels.
- Keep time-source private keys and root-signing private keys in separate
  approved custody domains.
- Choose radius and final-width limits from the decision's actual security
  window; the fixture's four-second interval is illustrative only.
- Preserve failing reports. Boundary failures are evidence of uncertainty, not
  permission to round toward acceptance.
- Feed SARIF into review workflows, but keep root installation and deployment
  authorization in explicit human-owned control planes.

## Explicit non-claims

The protocol does not prove UTC accuracy, source independence, clock or key
custody, legal identity, global root freshness, or that a distributor did not
withhold a newer root. It is not NTP, PTP, RFC 3161, Roughtime, TUF, PKI, FIPS,
compliance certification, an authorization to operate, deployment approval, or
risk acceptance. It performs zero network requests, clock adjustments, root
installations, key operations, notifications, or automatic actions.

## Design references

- [NIST SP 800-53 Rev. 5, SC-45](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
  motivates trustworthy and corroborated system time.
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) motivates binding a unique
  request value and message imprint to time evidence.
- [IETF Roughtime draft](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
  motivates signed midpoint-plus-radius responses bound to a client nonce.
- [The Update Framework specification](https://theupdateframework.github.io/specification/latest/)
  motivates fail-closed expiration and freeze-attack handling.

These are design inputs, not compatibility claims.
