# Mission Assurance Commons

Mission Assurance Commons is the end-to-end workflow for turning a bounded AI
use case and locally held operational evidence into reviewable, portable
assurance artifacts. The current Commons adds privacy-bounded telemetry,
temporal graphs, bounded authorization-race exploration, real-backend bridge
execution, signed community protocols, verified remediation, exact resilience
frontiers, and measured mission economics:

```text
public inventory ──→ reviewed/signed MissionPack ──→ synthetic twin tests
local OTLP export ─→ sanitized TraceProof evidence ─→ temporal graph tests
                 └──→ CollectiveGuard containment ─────┤
synthetic defense mission ─→ DefenderTwin fix proof ───┤
verified fix proofs ───────→ ResilienceGraph frontier ─┤
ScheduleProof race exploration ────────────────────────┤
harmless canary records ─→ ContainmentProof ───────────┤
AgentBOM baseline + candidate ─→ ClaimImpact ──────────┤
                                                       ↓
                                  AssuranceGraph executable case
                                            ↓
               federal review pack + public reproduction exchange
                                            ↓
                    drift comparison ← ContinuousProof
                              ↑        ← ValueProof ← acquisition review inputs
```

It is designed for program owners, evaluators, engineers, researchers, and
acquisition teams who need a shared technical artifact without delegating their
decision authority to a benchmark.

## Why this exists

Current U.S. guidance points to a practical gap between policy and execution:

- [OMB M-25-21](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-21-Accelerating-Federal-Use-of-AI-through-Innovation-Governance-and-Public-Trust.pdf)
  calls for ongoing evaluation, monitoring, independent review, and public AI
  use-case inventories.
- [OMB M-25-22](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf)
  emphasizes capability testing, mission outcomes, ongoing testing, pricing,
  portability, and vendor-lock-in planning.
- The [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
  highlights interoperable protocols, security, identity, and evaluations for
  agent systems.
- NIST's [agent identity and authorization concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
  frames least privilege, delegation, intent, action-authority proof, prompt
  injection, and tamper-evident logs as enterprise agent concerns.
- [GSA Buy AI](https://www.gsa.gov/artificial-intelligence/buy-ai) recommends
  scoped testbeds, sound data management, and cost monitoring.

The Commons implements technical inputs around those needs. Its crosswalks are
informative. Nothing here determines compliance, impact classification, source
selection, risk acceptance, or an authorization to operate.

## End-to-end workflow

### 1. Bound the mission with InventoryForge

```bash
dspy-security-bench inventory import public-inventory.csv --out inventory.json
dspy-security-bench inventory draft-pack inventory.json USE-CASE-ID --out mission-pack.yaml
dspy-security-bench pack validate mission-pack.yaml
```

The inventory record is secondary evidence. InventoryForge never treats it as
controlling policy, removes contact fields, and marks the output as a synthetic
draft requiring an accountable owner to replace assumptions and approve every
expected outcome.

### 2. Review and optionally sign the MissionPack

```bash
dspy-security-bench pack validate mission-pack.yaml
dspy-security-bench pack keygen \
  --private-key mission-pack-private.pem --public-key mission-pack-public.pem
dspy-security-bench pack sign mission-pack.yaml \
  --private-key mission-pack-private.pem --signer "owner-defined identity" \
  --out mission-pack.signed.json
dspy-security-bench pack verify-signature mission-pack.signed.json
```

Signature verification and content approval are intentionally distinct. See
the [Signed MissionPack Commons](mission-pack-commons.md).

### 3. Sanitize operational traces locally

```bash
dspy-security-bench trace import otlp-export.json \
  --policy traceproof-redaction.yaml --out artifacts/trace-evidence.json
dspy-security-bench trace analyze artifacts/trace-evidence.json \
  --out artifacts/trace-report.json --sarif-out artifacts/trace.sarif
```

TraceProof removes raw prompts, arguments, secrets, identifiers, and
unapproved attributes before analysis. The input and artifacts stay in the
operator's custody. Read the [TraceProof privacy boundary](traceproof.md).

### 4. Exercise identity and delegation with AgentGraphTwin

```bash
dspy-security-bench graph describe
dspy-security-bench graph demo
dspy-security-bench graph run --adapter myapp.authority:build_adapter \
  --json-out artifacts/agent-graph.json
dspy-security-bench graph verify artifacts/agent-graph.json
dspy-security-bench graph v2-run \
  --adapter myapp.authority:build_temporal_adapter \
  --json-out artifacts/agent-graph-v2.json
dspy-security-bench graph v2-verify artifacts/agent-graph-v2.json
```

The six graph twins cover confused deputy behavior, scope amplification,
revoked intermediate authority, cross-tenant branches, parallel approval
replay, and intent drift before a tool call.

v2 adds token-exchange audience binding, delegation continuity, step-up
ordering, revocation latency, parallel approval races, and multi-effect
boundaries. A live AuthorityBridge can exercise an operator-controlled OPA,
Cedar, OpenFGA, OAuth-bound MCP, or SPIFFE command using a bounded JSON
contract; its execution claim remains self-attested.

### 5. Test collective containment with CollectiveGuard

```bash
dspy-security-bench collective init \
  --profile hardened-collective --out collectiveguard.json
dspy-security-bench collective run collectiveguard.json \
  --json-out artifacts/collectiveguard.json \
  --sarif-out artifacts/collectiveguard.sarif \
  --fail-on-findings --require-timely-containment
```

CollectiveGuard uses identifiers, categorical events, and relative offsets to
measure cross-run communication, indirect egress, peer-authority laundering,
credential and evaluator boundaries, safe-stop behavior, incident response,
restart approval, and control independence. It processes no prompts, reasoning,
messages, tool I/O, credentials, or exploit payloads. See the
[CollectiveGuard protocol](collectiveguard.md).

### 6. Prove remediation effectiveness with DefenderTwin

```bash
dspy-security-bench defend demo --out-dir artifacts/verified-defense
```

DefenderTwin recomputes whether a bounded synthetic remediation closes declared
attack paths, stays within target/action/approval scope, preserves essential
services, introduces no declared risk, retains rollback, and has complete
evidence. It executes no live change. See the
[Verified Cyber Defense Commons](verified-cyber-defense-commons.md).

### 7. Plan the exact defense frontier with ResilienceGraph

```bash
dspy-security-bench portfolio init --out resilience-campaign.json
dspy-security-bench portfolio run resilience-campaign.json \
  --json-out artifacts/resilience-report.json \
  --csv-out artifacts/resilience-frontier.csv \
  --require-fully-robust
```

ResilienceGraph excludes unsafe DefenderTwin candidates, enumerates every
bounded subset, applies owner resource, concentration, service, and community
constraints, replays declared availability scenarios, and exposes every
non-dominated portfolio. The reference is deterministic and explicitly not a
recommendation. See the [ResilienceGraph guide](resiliencegraph.md).

### 8. Explore every declared authorization interleaving with ScheduleProof

```bash
dspy-security-bench schedule init \
  --profile hardened-payment --out scheduleproof.json
# Replace the starter events and happens-before edges with the reviewed design.
dspy-security-bench schedule run scheduleproof.json \
  --json-out artifacts/scheduleproof.json \
  --sarif-out artifacts/scheduleproof.sarif \
  --fail-on-unsafe --require-complete
dspy-security-bench schedule verify artifacts/scheduleproof.json
```

ScheduleProof counts every topological ordering of the declared graph and
exhaustively checks up to 100,000 schedules for active authority, prior and
single-use approval, resource-bound token exchange, scope attenuation, identity
and audience continuity, and replay-safe effect receipts. A bounded-safe result
applies only to the supplied atomic-event model; the explored unsafe fraction
is not a runtime probability. Read the [ScheduleProof guide](scheduleproof.md).

### 9. Detect evidence drift with ContinuousProof

```bash
dspy-security-bench watch baseline artifacts/agent-graph.json \
  --label approved-baseline --out artifacts/baseline.json
# Capture a new verified snapshot after a model, policy, tool, or data change.
dspy-security-bench watch compare artifacts/baseline.json artifacts/candidate.json \
  --max-regression 0.02 --out artifacts/drift.json
```

Thresholds are owner supplied. A `review` result is a change signal, not an
automatic deployment rejection or risk decision.

### 10. Add owner-measured mission economics

```bash
dspy-security-bench value build value-observation.json \
  --out artifacts/valueproof.json
dspy-security-bench value verify artifacts/valueproof.json
```

ValueProof makes observed cost per safe mission, latency, review, recovery, and
portability arithmetic reproducible. It does not estimate savings or rank a
vendor. Read the [ValueProof measurement guide](valueproof.md).

### 11. Package comparable acquisition inputs

```bash
dspy-security-bench acquisition init --out acquisition-profile.json
# Edit the mission, objectives, owner, pricing fields, and triggers.
dspy-security-bench acquisition validate acquisition-profile.json
dspy-security-bench acquisition export artifacts/agent-graph.json \
  --profile acquisition-profile.json --out artifacts/acquisitionproof
dspy-security-bench acquisition verify artifacts/acquisitionproof
```

The pack contains source evidence, owner-defined QASP objective inputs, a
vendor-neutral mission test plan, portability and exit checks, empty cost
observation fields, and reevaluation triggers. It does not rank or recommend a
vendor.

### 12. Compile an executable assurance case with AssuranceGraph

```bash
dspy-security-bench assure init --profile federal-high-impact \
  --case-id reviewed-agent-pilot --out assurance-case.json
dspy-security-bench assure evaluate assurance-case.json \
  --evidence-root . --out artifacts/assurance-report.json \
  --sarif-out artifacts/assurance.sarif \
  --oscal-out artifacts/assessment-results.json \
  --html-out artifacts/assurance.html --fail-on-review
```

AssuranceGraph recomputes every referenced report through its native verifier,
checks frozen profile predicates, preserves missing, stale, violated, and
contradictory evidence, and binds the result to canonical evidence content,
owners, boundary, and evaluation time. It is an engineering review surface—not
certification, ATO, deployment approval, or risk acceptance. Read the
[AssuranceGraph protocol](assurancegraph.md).

### 13. Prove evaluation integrity, runtime controls, and dependency currency

```bash
dspy-security-bench evalguard demo --out-dir artifacts/eval-integrity
dspy-security-bench contain demo --out-dir artifacts/containmentproof
dspy-security-bench bom demo --out-dir artifacts/agentbom
dspy-security-bench assure init --sector water-operations \
  --case-id water-agent-pilot --out assurance-case.json
```

EvalIntegrityProof verifies content-free holdout, evaluator, monitor,
commit/reveal, accounting, and safe-exit evidence. ContainmentProof keeps
control violations, monitor failures, and incomplete evidence separate across
eight harmless canaries. AgentBOM ClaimImpact maps a
changed dependency through the exact claims that need reevaluation. The
declarative probe contract cannot load contributor code. Verified cases can be
exported as a closed federal review pack or indexed in the non-ranking public
exchange. Read the [Assurance Control Plane guide](assurance-control-plane.md).

## Contribution targets

The Commons will become useful through independent evidence, not feature count.
The next measurable community targets are:

1. five independently maintained real-backend AuthorityBridge integrations;
2. three agency or domain-owner-reviewed, fully synthetic mission packs;
3. ten externally generated TraceProof or twin evidence bundles;
4. three sector-reviewed fictional ResilienceGraph campaigns with independently
   reproduced frontier counts;
5. three organization-reviewed AssuranceGraph cases built only from synthetic
   or safely publishable evidence, including at least one unfavorable outcome;
6. three independently reproduced EvalIntegrityProof records, including one
   monitor failure or integrity violation;
7. two independent reproductions; and
8. one published deployment or research report describing limitations.

These are targets, not current claims. Reference fixtures and maintainer-created
synthetic examples do not count as independent evidence.

## Safety and data boundary

- Inputs are local `.csv`, `.json`, or data-only MissionPacks; InventoryForge
  performs no fetch and preserves no contact field.
- TraceProof processes local OTLP JSON without a collector connection and
  removes content and unapproved attributes by default; pseudonyms remain
  linkable and are not anonymization.
- Benchmark tools use fictional principals, resources, approvals, costs, and
  effects. No real payment, isolation, account, or network mutation occurs.
- ScheduleProof consumes a declared atomic-event graph and executes nothing. It
  cannot discover omitted events or establish production scheduler behavior.
- CollectiveGuard consumes an owner-supplied structural event record and cannot
  prove that telemetry is complete or that an unobserved violation did not occur.
- Adapters are an external trust boundary. The harness records normalized
  outputs but does not own production identity, credentials, or policy.
- Hashes make local evidence tamper evident. They are not signatures,
  non-repudiation, or proof that a hosted model was independently observed.
- Ed25519 MissionPack signatures prove key possession and artifact integrity,
  not content authority, approval, safety, or government origin.
- Accountable humans retain mission design, thresholds, legal interpretation,
  accessibility, privacy, records, acquisition, security, and deployment
  decisions.
