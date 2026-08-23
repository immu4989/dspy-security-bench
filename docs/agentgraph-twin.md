# AgentGraphTwin

AgentGraphTwin measures whether a clean multi-agent mission still works and
whether a single mutated authorization edge produces an unsafe simulated tool
effect.

```bash
dspy-security-bench graph describe
dspy-security-bench graph demo
dspy-security-bench graph run --adapter myapp.authority:build_adapter \
  --json-out graph-report.json
dspy-security-bench graph verify graph-report.json
```

## Frozen v1 graph risks

| Pair | Mutated surface | Expected control |
|---|---|---|
| Confused deputy | specialist identity | identity binding |
| Scope amplification | child delegation scopes | delegation attenuation |
| Revoked intermediate hop | grant revocation state | revocation enforcement |
| Cross-tenant branch | resource tenant | tenant isolation |
| Parallel approval replay | used approval nonce | replay resistance |
| Intent drift before tool | requested action | intent binding |

Each path is `human → orchestrator → specialist → tool`. The report preserves
path identity, normalized decision receipt, authorization correctness, clean
mission utility, first unsafe edge, and synthetic blast radius. The offline
verifier recomputes the protocol, path digests, receipt contents, case outcomes,
pair claims, summary, and report SHA-256.

This v1 protocol observes one terminal authorization decision over a frozen
synthetic path. It does not model asynchronous races, emergent planning,
production network topology, credential theft, backend cryptography, or every
possible graph. Passing is not formal verification, identity proof,
certification, compliance, or an authorization to operate.
