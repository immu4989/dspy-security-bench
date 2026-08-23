# AuthorityBridge contracts

AuthorityBridge connects an existing policy or identity decision to the small
`AuthorityAdapter` contract used by AuthorityTwin and AgentGraphTwin.

```bash
dspy-security-bench authority bridge list
dspy-security-bench authority bridge demo opa
dspy-security-bench authority bridge scaffold openfga --out authority_adapter.py
```

The bundled contracts cover OPA, Cedar, OpenFGA, OAuth-bound MCP tools, and
SPIFFE workload identity. Every starter is deny-by-default and makes credential
loading and backend invocation the adopter's responsibility.

## Exercise an operator-controlled backend

The live runner sends each canonical AuthorityTwin request as one JSON object
on stdin and expects one backend-native response object on stdout. It invokes
the declared command directly without a shell, applies a timeout, rejects
non-JSON output, and translates the response through the named bridge.

```bash
dspy-security-bench authority bridge run opa \
  --backend-version 1.10.0 \
  --command "./evaluate-authority" \
  --timeout 15 \
  --json-out artifacts/opa-live-authority.json
dspy-security-bench authority bridge verify \
  artifacts/opa-live-authority.json
```

The evidence records the backend name/version, a SHA-256 of the command string,
the normalized AuthorityTwin report, and a canonical evidence digest. It does
not record the command text, credentials, environment, or raw backend policy.
Execution metadata is self-attested. Run only commands you trust, in an
appropriately isolated environment; this feature intentionally does not load
credentials or start a backend for you.

The response shapes are the same as the translation fixtures. For example, OPA
returns a `result` object, Cedar an authorization decision, OpenFGA an `allowed`
check, OAuth-bound MCP a token/tool decision, and SPIFFE a workload-identity
decision. Start with `authority bridge scaffold` to see the exact mapping.

## What compatibility means

The dependency-free demos execute a bounded reference policy, encode its result
in the named backend's response shape, translate that response, and run the
frozen AuthorityTwin protocol. This validates the translation contract only.
It does **not** execute, test, certify, or endorse the named product, SDK,
deployment, identity, policy, or cryptography.

Real compatibility evidence should:

1. pin the backend, SDK, policy, and adapter source versions;
2. run a real local or test backend against the frozen protocol;
3. exclude credentials and sensitive request arguments;
4. publish complete repeated evidence rather than a screenshot; and
5. describe gaps between the normalized contract and production enforcement.

See [AuthorityTwin](authority-twin.md) for the adapter and receipt contract.
