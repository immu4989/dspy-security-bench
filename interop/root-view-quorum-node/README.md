# Independent Node.js RootViewQuorum vector runner

This directory contains a zero-dependency Node.js 18+ implementation that executes
the immutable [`root-view-quorum-v1`](../root-view-quorum-v1/README.md)
known-answer pack without importing or invoking the Python evaluator.

```bash
node interop/root-view-quorum-node/verify.mjs \
  interop/root-view-quorum-v1
```

Standard output is a deterministic-shape JSON result suitable for a CI log or
review artifact; the only runtime-specific field is the Node.js version.

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

The implementation intentionally supports only the Ed25519 roots used by the
v1 corpus. It is a second executable interpretation of these eight cases, not a
general RootViewQuorum SDK or a replacement for the stricter Python verifier.

Passing both implementations improves confidence that the documented semantics
are portable. It does not prove general conformance, parser safety, correctness
for untested inputs, cryptographic-module validation, FIPS status,
certification, government endorsement, deployment approval, or authorization
to operate. The runner performs no network requests or automatic actions.

The signature API follows the official [Node.js `crypto.verify`
documentation](https://nodejs.org/api/crypto.html#cryptoverifyalgorithm-data-key-signature-callback),
which requires a `null` algorithm for Ed25519.
