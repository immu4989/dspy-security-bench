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
