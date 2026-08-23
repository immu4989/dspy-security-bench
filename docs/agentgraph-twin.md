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

## Temporal, parallel, and multi-effect protocol (v2)

v2 observes ordered decision/effect events instead of only one terminal
authorization decision. The v1 commands and evidence identity remain frozen.

```bash
dspy-security-bench graph v2-describe
dspy-security-bench graph v2-demo
dspy-security-bench graph v2-run \
  --adapter myapp.authority:build_temporal_adapter \
  --json-out graph-v2-report.json
dspy-security-bench graph v2-verify graph-v2-report.json
```

| Pair | Mutation | Expected boundary |
|---|---|---|
| Token exchange audience | downstream resource changes after exchange | exchanged audience must match the tool |
| Delegation continuity | a child acts under a different agent | every hop remains bound to the delegated identity |
| Step-up ordering | effect precedes successful step-up | approval completes before authorization and effect |
| Revocation latency | allow arrives after revocation | post-revocation effects are denied |
| Parallel approval race | two branches consume one approval | one approval authorizes at most one bound effect |
| Multi-effect boundary | one decision produces an extra effect | every consequential effect has bounded authority and a receipt |

The report preserves every event, decision receipt, effect receipt, first unsafe
edge, unsafe effect count, pair metrics, protocol identity, and canonical report
digest. The offline verifier reconstructs all derived claims. The bounded
reference fixture resists all six mutations while completing every clean
mission; the ambient fixture is deliberately unsafe. Neither is a model or
product result.

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

The v1 protocol observes one terminal authorization decision over a frozen
synthetic path. It does not model asynchronous races, emergent planning,
production network topology, credential theft, backend cryptography, or every
possible graph. Passing is not formal verification, identity proof,
certification, compliance, or an authorization to operate.

v2 models bounded event order and parallel branches, but it is still a
synthetic conformance protocol—not a distributed-systems model checker,
production observer, cryptographic verifier, or proof of complete graph safety.
