# Cross-language interoperability lab

This directory turns selected assurance protocols into executable contracts
that another language can implement without importing the Python package.

| Contract | Frozen inputs | Independent implementations | Differential checks |
|---|---:|---:|---:|
| RootViewQuorum v1 | 8 cases / 21 bound artifacts | Python + zero-dependency Node.js | 21 self-rehashed mutations |

Start here:

```bash
# Reference package verifier
dspy-security-bench ledger verify-root-view-vectors \
  interop/root-view-quorum-v1

# Independent implementation
node interop/root-view-quorum-node/verify.mjs \
  interop/root-view-quorum-v1
```

The known-answer corpus has an immutable manifest identity. Each runner emits
machine-readable results; the Node result also binds the exact verifier source
bytes by SHA-256. Pull-request CI executes both implementations and applies the
differential mutation suite.

Preserve a successful run as portable, exactly recomputable evidence:

```bash
node interop/root-view-quorum-node/verify.mjs \
  interop/root-view-quorum-v1 > root-view-node-result.json
dspy-security-bench ledger evaluate-root-view-interop \
  interop/root-view-quorum-v1 root-view-node-result.json \
  --implementation-source interop/root-view-quorum-node/verify.mjs \
  --implementation-language javascript \
  --out root-view-interop.report.json
```

The report binds the corpus and exact verifier sources as in-toto Statement
subjects and retains all eight agreements. It is unsigned and does not prove
which code executed; pair it with authenticated CI provenance for that claim.

## Add another implementation

A useful implementation contribution should:

1. live in its own `interop/root-view-quorum-<language>/` directory;
2. use only that language's standard library where practical;
3. import or execute neither the Python nor Node verifier;
4. accept the committed pack path as an argument;
5. recompute the immutable manifest, file digests, signatures, classifications,
   thresholds, reports, and expected decisions rather than matching filenames;
6. emit JSON containing an implementation ID, exact source digest, manifest
   digest, ordered case results, and zero automatic actions;
7. reject symlinks, undeclared files, unsafe relative paths, oversized inputs,
   malformed keys/signatures, and self-rehashed semantic tampering;
8. include an offline test and a CI step;
9. produce and reverify a `RootViewInteropEvidence` report from its result; and
10. state precisely which protocol subset and signature schemes it supports.

Do not change the v1 corpus in place. A semantic change requires a new vector
version and directory so existing implementation results keep one meaning.

Never add private keys, credentials, production roots, internal endpoints,
controlled data, or real organization identifiers. Fixed generator seeds are
public test material only. Conformance to a finite corpus is not certification,
FIPS validation, compliance, government endorsement, deployment approval, or
an authorization to operate.
