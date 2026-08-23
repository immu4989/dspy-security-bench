# Mission Assurance Commons

Mission Assurance Commons is the end-to-end workflow for turning a bounded AI
use case and locally held operational evidence into reviewable, portable
assurance artifacts. v0.16 adds privacy-bounded telemetry, temporal graphs,
real-backend bridge execution, signed community protocols, and measured mission
economics:

```text
public inventory ──→ reviewed/signed MissionPack ──→ synthetic twin tests
local OTLP export ─→ sanitized TraceProof evidence ─→ temporal graph tests
                                                       ↓
                    drift comparison ← ValueProof ← acquisition review inputs
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

### 5. Detect evidence drift with ContinuousProof

```bash
dspy-security-bench watch baseline artifacts/agent-graph.json \
  --label approved-baseline --out artifacts/baseline.json
# Capture a new verified snapshot after a model, policy, tool, or data change.
dspy-security-bench watch compare artifacts/baseline.json artifacts/candidate.json \
  --max-regression 0.02 --out artifacts/drift.json
```

Thresholds are owner supplied. A `review` result is a change signal, not an
automatic deployment rejection or risk decision.

### 6. Add owner-measured mission economics

```bash
dspy-security-bench value build value-observation.json \
  --out artifacts/valueproof.json
dspy-security-bench value verify artifacts/valueproof.json
```

ValueProof makes observed cost per safe mission, latency, review, recovery, and
portability arithmetic reproducible. It does not estimate savings or rank a
vendor. Read the [ValueProof measurement guide](valueproof.md).

### 7. Package comparable acquisition inputs

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

## Contribution targets

The Commons will become useful through independent evidence, not feature count.
The next measurable community targets are:

1. five independently maintained real-backend AuthorityBridge integrations;
2. three agency or domain-owner-reviewed, fully synthetic mission packs;
3. ten externally generated TraceProof or twin evidence bundles;
4. two independent reproductions; and
5. one published deployment or research report describing limitations.

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
- Adapters are an external trust boundary. The harness records normalized
  outputs but does not own production identity, credentials, or policy.
- Hashes make local evidence tamper evident. They are not signatures,
  non-repudiation, or proof that a hosted model was independently observed.
- Ed25519 MissionPack signatures prove key possession and artifact integrity,
  not content authority, approval, safety, or government origin.
- Accountable humans retain mission design, thresholds, legal interpretation,
  accessibility, privacy, records, acquisition, security, and deployment
  decisions.
