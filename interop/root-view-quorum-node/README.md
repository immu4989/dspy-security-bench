# Independent Node.js RootViewQuorum vector runner

This directory contains a zero-dependency Node.js 18+ implementation that executes
the immutable [`root-view-quorum-v1`](../root-view-quorum-v1/README.md)
known-answer pack without importing or invoking the Python evaluator.

```bash
node interop/root-view-quorum-node/verify.mjs \
  interop/root-view-quorum-v1
```

Standard output is a deterministic-shape JSON result suitable for a CI log or
review artifact. It binds the exact verifier source bytes by SHA-256; the only
runtime-specific field is the Node.js version.

Turn that result into a strict, source-bound interoperability retention
artifact with `ledger evaluate-root-view-interop`; the complete command and
claim boundary are in the [interoperability lab](../README.md).

Verify a standalone RootViewQuorum report and receive a machine-readable
accept/reject result:

```bash
node interop/root-view-quorum-node/verify.mjs \
  --report root-view.report.json
```

`accepted` means the report recomputes and verifies; it does not mean the root
view is favorable. Read `evidence_status` separately—for example, a correctly
verified `same_version_root_conflict` report is accepted evidence of a blocking
condition.

The runner uses only Node.js built-ins. It independently checks:

- the pinned v1 manifest identity and its recomputed digest;
- the exact 21 declared file digests and absence of symlinks or undeclared files;
- canonical JSON SHA-256 identities;
- embedded Ed25519 SPKI key identities and signatures;
- current trust-root signature and organization thresholds;
- observer policy, candidate-root, nonce, identity, organization, and key binding;
- matching, lagging, same-version-conflict, and newer-root classification;
- unique-observer and distinct-organization quorum semantics;
- all seven expected report outcomes; and
- rejection of the self-rehashed derived-summary mutation.

For embedded trust roots it supports every RootViewQuorum v1 scheme: Ed25519,
ECDSA P-256/SHA-256, and RSA-PSS/SHA-256 with a 32-byte salt. Observer receipts
remain Ed25519 as required by the protocol. The test suite also applies 21
self-rehashed mutations across every summary field, findings, receipt results,
metadata, limitations, and a receipt signature; both Python and Node must
reject every mutation.

This is a second executable interpretation and standalone report verifier, not
a published npm SDK.

Passing both implementations improves confidence that the documented semantics
are portable. It does not prove general conformance, parser safety, correctness
for untested inputs, cryptographic-module validation, FIPS status,
certification, government endorsement, deployment approval, or authorization
to operate. The runner performs no network requests or automatic actions.

The signature API follows the official [Node.js `crypto.verify`
documentation](https://nodejs.org/api/crypto.html#cryptoverifyalgorithm-data-key-signature-callback),
which requires a `null` algorithm for Ed25519.
