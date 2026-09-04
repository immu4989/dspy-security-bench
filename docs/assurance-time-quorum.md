# AssuranceTimeQuorum

AssuranceTimeQuorum produces portable, independently signed **bounded-time
evidence** for one exact artifact and one fresh verifier challenge. It addresses
a narrow but consequential problem: expiration, freshness, and incident
timelines are only as trustworthy as the clock used to evaluate them.

It does not set a clock. It does not assert a perfectly precise time. It asks
multiple policy-pinned sources to sign intervals and returns only their
conservative overlap.

When the subject is an AssuranceTrustRoot, the
[TrustRootTimeGate](trust-root-time-gate.md) consumes this interval without
rounding it to a favorable point and requires root trust at both endpoints.

```text
artifact SHA-256 + fresh caller nonce
               │
       ┌───────┼────────┐
       ▼       ▼        ▼
    source A source B source C     distinct declared organizations
     [997,   [999,     [999,
      1003]   1005]     1003]
       └───────┼────────┘
               ▼
       intersection [999, 1003]
       width 4 seconds · no averaging
```

## Why this exists

Several assurance decisions rely on time:

- whether a trust root or policy is issued and unexpired;
- whether a recovery drill is recent enough;
- whether recovery handoffs met response windows;
- whether a ContinuousProof observation is stale; and
- whether an event preceded revocation or compromise.

A caller-supplied integer is deterministic, but it is not evidence that the
caller's clock was correct. NIST SP 800-53 control SC-45 calls for system time
synchronization and defines enhancements for authoritative and secondary
sources. RFC 3161 requires a time-stamping authority to use a trustworthy time
source and bind a unique value to a time-stamp request. The experimental IETF
Roughtime work signs a response derived from a client nonce and returns a time
with an uncertainty radius. TUF documents how stale timestamp metadata can
enable a freeze attack.

AssuranceTimeQuorum combines only the portable properties useful to this repo:
explicit source policy, caller challenge binding, signatures, uncertainty, and
source diversity. It does **not** claim compatibility with those protocols.

## Ten deterministic checks

| Rule | Requirement |
|---|---|
| `ATQ001` | Exact time-policy digest matches the independent caller pin |
| `ATQ002` | Policy shape, Ed25519 keys, thresholds, and digest validate |
| `ATQ003` | Every receipt has the exact v1 statement shape and context |
| `ATQ004` | Every receipt binds the expected artifact digest and fresh nonce |
| `ATQ005` | Source identity, organization, and key match the policy |
| `ATQ006` | Every Ed25519 signature verifies over the canonical statement |
| `ATQ007` | Radius is allowed and lower/upper bounds derive exactly |
| `ATQ008` | Enough unique sources supplied valid receipts |
| `ATQ009` | Enough distinct declared source organizations participated |
| `ATQ010` | Intervals overlap and the conservative width is allowed |

Outcomes remain distinct:

- `bounded_time_corroborated`
- `invalid_time_evidence`
- `time_policy_not_pinned`
- `time_request_mismatch`
- `insufficient_time_sources`
- `insufficient_time_source_diversity`
- `time_sources_inconsistent`
- `time_uncertainty_too_wide`

## Try the complete fictional fixture

```bash
dspy-security-bench ledger demo --out-dir artifacts/assurance-ledger

dspy-security-bench ledger verify-time-quorum \
  artifacts/assurance-ledger/time-quorum.report.json
```

The demo includes:

- `time-quorum-policy.json`;
- three independently signed `time-source-*.receipt.json` files;
- `time-quorum.report.json`; and
- `time-quorum.sarif`.

The keys, organizations, timestamps, and nonce are fictional. Demo private keys
are created in a temporary directory and discarded.

## Build a deployment-owned policy

First describe each Ed25519 public key. Keep the private keys at their
independently administered sources.

```bash
dspy-security-bench ledger describe-time-source source-a.public.pem \
  --source-id source-a \
  --organization-id organization-a \
  --out source-a.json
```

Use `build_time_policy()` to combine two to fifty descriptors and choose:

- a minimum number of unique sources;
- a minimum number of distinct declared organizations;
- the largest acceptable radius per source; and
- the largest acceptable final intersection width.

Distribute the resulting `policy_sha256` through an independent, owner-governed
channel. A self-declared pin inside an untrusted report does not establish
trust.

## Request and issue receipts

The verifier chooses:

1. the SHA-256 digest of the exact artifact being time-bounded; and
2. a fresh, unpredictable nonce retained with the request context.

Each source returns its midpoint and conservative uncertainty radius:

```bash
dspy-security-bench ledger issue-time-receipt time-policy.json \
  source-a.private.pem \
  --source-id source-a \
  --subject-sha256 "$SUBJECT_SHA256" \
  --request-nonce "$FRESH_RANDOM_NONCE" \
  --midpoint-unix 1819700000 \
  --radius-seconds 3 \
  --out source-a.receipt.json
```

The source signs the policy digest, trust domain, subject digest, nonce,
identity tuple, midpoint, radius, and exact derived bounds. Receipts for a
different subject or challenge cannot be silently reused.

## Evaluate without averaging away disagreement

```bash
dspy-security-bench ledger evaluate-time-quorum time-policy.json \
  source-a.receipt.json source-b.receipt.json source-c.receipt.json \
  --expected-policy-sha256 "$PINNED_POLICY_SHA256" \
  --subject-sha256 "$SUBJECT_SHA256" \
  --request-nonce "$FRESH_RANDOM_NONCE" \
  --out time-quorum.report.json \
  --sarif-out time-quorum.sarif \
  --fail-on-time
```

The analyzer calculates:

```text
lower bound = maximum(all source lower bounds)
upper bound = minimum(all source upper bounds)
```

It never takes a mean or votes on a timestamp. Empty overlap is disagreement,
not a value to smooth over. An overlap wider than the policy limit is
insufficient precision, not a passing result.

When accepting a saved report, repeat the external expectations if available:

```bash
dspy-security-bench ledger verify-time-quorum time-quorum.report.json \
  --expected-policy-sha256 "$PINNED_POLICY_SHA256" \
  --subject-sha256 "$SUBJECT_SHA256" \
  --request-nonce "$FRESH_RANDOM_NONCE"
```

## Operational boundary

A passing report proves that the policy-authorized keys signed overlapping
intervals for the exact subject and nonce. It does not prove:

- legal identity or actual organizational independence;
- correct synchronization to UTC, NIST, GPS, PTP, or any other authority;
- trustworthy source hardware, software, custody, or administration;
- that a nonce was actually fresh unless the verifier retained it;
- RFC 3161 or Roughtime wire compatibility;
- that an artifact was safe, approved, or authorized; or
- compliance, an authorization to operate, or risk acceptance.

The report processes zero artifact-content fields, performs zero clock
adjustments, and takes zero automatic actions. Deployment owners remain
responsible for source selection, policy-pin distribution, nonce generation,
network acquisition, clock discipline, retention, and incident response.

## Authoritative design references

- [NIST SP 800-53 Rev. 5, SC-45 System Time Synchronization](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SP 800-82 Rev. 3, OT Security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [RFC 3161, Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161)
- [IETF Roughtime Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
- [The Update Framework specification](https://theupdateframework.github.io/specification/latest/)
