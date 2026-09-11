# RootViewQuorum v1 known-answer vectors

This directory is a deterministic, language-neutral interoperability corpus for
implementers of `assuranceledger-root-view-quorum-v1`.

It contains public trust roots, observer policy and receipts, seven exactly
recomputable evaluation reports, one rehashed semantic-tampering report that
must be rejected, and a manifest binding every JSON file by SHA-256. No private
keys are included. The generator's fixed key seeds are intentionally public and
test-only; never reuse them outside fixtures.

Verify all file bytes and execute all eight cases:

```bash
dspy-security-bench ledger verify-root-view-vectors \
  interop/root-view-quorum-v1
```

Regenerate the same bytes into a fresh directory:

```bash
dspy-security-bench ledger generate-root-view-vectors \
  --out-dir /tmp/root-view-quorum-v1

diff -ru --exclude README.md interop/root-view-quorum-v1 /tmp/root-view-quorum-v1
```

The committed README is explanatory and is the only file permitted outside the
JSON-file digest set. Symlinks and any other undeclared files are rejected.
`vector-manifest.json` is self-digested and binds every JSON input,
receipt, root, report, expected outcome, and verifier decision.
The v1 verifier also pins the official manifest digest
`e39be2384f1ff8e49d8e62e26df112a01d181e5ece06a9e9f7df36dd93750e08`,
so an edited and self-rehashed corpus cannot impersonate this known-answer set.

Passing these vectors demonstrates behavior only for this finite corpus. It is
not general conformance, NIST ACVP/CAVP or FIPS validation, certification,
government endorsement, deployment approval, or an authorization to operate.

See the [RootViewQuorum protocol guide](../../docs/root-view-quorum.md) for the
security model, operating procedure, and exact non-claims.
