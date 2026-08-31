# EvalIntegrityProof: prove the evaluation before trusting the score

EvalIntegrityProof answers a question that benchmark provenance alone cannot:

> Did one AI-agent evaluation preserve its declared holdout, evaluator,
> monitoring, identity, network, accounting, and safe-exit boundaries?

It consumes a content-free structural record and produces a sealed,
deterministically recomputable report. It never loads a model, runs an
evaluator, reveals a holdout, reads a prompt or output, touches credentials,
contacts a network, stops a workload, or approves deployment.

This complements two existing layers:

- **ProofRun** authenticates which workflow produced exact result bytes.
- **ContainmentProof** checks harmless runtime and response canaries.
- **EvalIntegrityProof** checks whether the evaluation process itself preserved
  its declared separation and ordering properties.

No one layer substitutes for the others.

## Five-minute offline demo

```bash
git clone https://github.com/immu4989/dspy-security-bench.git
cd dspy-security-bench
uv sync --locked --extra dev

uv run dspy-security-bench evalguard demo --out-dir artifacts/eval-integrity
uv run dspy-security-bench evalguard verify \
  artifacts/eval-integrity/integrity-reference.report.json
```

The demo writes four explicitly fictional outcomes:

```text
integrity-reference  → integrity_evidenced
label-leakage        → integrity_violated
monitor-gap          → monitor_failed
incomplete-record    → incomplete_evidence
```

Each profile emits a sealed input record, a JSON report, and SARIF 2.1.0. The
unfavorable outcomes are fixtures, not findings about a model, vendor, or
deployed system.

## Thirteen frozen controls

| ID | Evidence question |
|---|---|
| `EI001` | Are the workload, evaluator, environment, committed case set, and scoring policy pinned by digest? |
| `EI002` | Was the holdout committed before the run began? |
| `EI003` | Was the result committed before labels were revealed? |
| `EI004` | Did workload and evaluator use different declared failure domains? |
| `EI005` | Could the workload read evaluator state or unrevealed labels? |
| `EI006` | Did workload and evaluator use different credential scopes? |
| `EI007` | Was egress denied or simulated, with no unauthorized egress observed? |
| `EI008` | Does every planned case end as committed or safely stopped? |
| `EI009` | Was leakage-canary monitoring active, and did it report zero hits? |
| `EI010` | Was the monitor declared independent and complete? |
| `EI011` | Was a safe exit available without forced unsafe continuation? |
| `EI012` | Does the record exclude raw prompts, outputs, and credential values? |
| `EI013` | Did observed clock skew remain inside the declared ordering tolerance? |

The protocol hash freezes these definitions, evidence paths, outcome semantics,
claim boundary, and limitations. A changed protocol produces a changed hash.

## Create an organization-owned record

```bash
dspy-security-bench evalguard init --out evaluation-integrity.json
```

Replace every fictional value with observations owned by your organization:

- artifact digests and the case-set commitment;
- UTC commit, start, result, and label-reveal timestamps;
- planned, started, committed, and safely stopped case counts;
- opaque failure-domain and credential-scope identifiers;
- evaluator-state, label-store, egress, and safe-exit observations;
- monitor completeness, independence, clock skew, and canary-hit count; and
- evidence-source ownership and completeness declarations.

Do not add prompts, outputs, labels, credential values, exploit material, or
production access. Unknown fields fail validation, and the CLI performs only
local JSON reads and writes.

Analyze and gate CI:

```bash
dspy-security-bench evalguard run evaluation-integrity.json \
  --json-out evaluation-integrity.report.json \
  --sarif-out evaluation-integrity.sarif \
  --fail-on-review
```

`--fail-on-review` writes the evidence first and returns nonzero unless the
outcome is `integrity_evidenced`.

## Outcome semantics

| Outcome | Exact meaning |
|---|---|
| `integrity_evidenced` | All 13 structural conditions are met and their bound sources are declared complete with an independent source present. |
| `integrity_violated` | At least one supplied observation contradicts a frozen integrity control. |
| `monitor_failed` | No integrity violation takes precedence, but an active canary, independent monitor, or clock-integrity condition failed. |
| `incomplete_evidence` | Conditions appear favorable, but bound evidence is incomplete or lacks an independent source. |

Precedence is deliberately fail-closed: an observed violation is never hidden
by incomplete evidence, and a monitor failure is never presented as a clean
result.

## AssuranceGraph and ContinuousProof

`evaluation-integrity` is a native evidence kind. AssuranceGraph verifies the
entire report before evaluating the `evaluation-process-integrity` claim, and
its enterprise, frontier-lab, federal-high-impact, and critical-infrastructure
profiles now require that claim. ContinuousProof can snapshot and compare the
same report without trusting arbitrary JSON.

The critical-infrastructure demo therefore composes nine evidence kinds:
AuthorityTwin, TraceProof, CollectiveGuard v2, ScheduleProof, DefenderTwin,
ResilienceGraph, EvalIntegrityProof, ContainmentProof, and AgentBOM ClaimImpact.

## Why this helps

- **Frontier labs** can distinguish a capable model result from an evaluation
  whose labels, evaluator state, egress, or monitoring boundary was exposed.
- **Government programs** can bind test procedure integrity into a reviewable
  evidence case without treating the tool as an ATO or compliance engine.
- **Cybersecurity teams** can send violations and monitor gaps to SARIF while
  retaining exact source bindings and non-claims.
- **Technology partners** can exchange content-free proof inputs without
  disclosing customer prompts, holdouts, outputs, or credentials.
- **Researchers** get a falsifiable commit/reveal and accounting protocol that
  separates measurement integrity from the benchmark score.

The design follows NIST's direction toward [machine-readable audit trails and
adversarial evaluation probes for agentic
AI](https://www.nist.gov/programs-projects/building-evaluation-probes-agentic-ai).
It also responds to the evaluation-isolation, monitoring, safe-exit, and
incident-response failure modes described in OpenAI's [Hugging Face incident
report and road ahead](https://openai.com/index/hugging-face-incident-and-the-road-ahead/).
Those sources motivate the problem; they do not endorse this implementation.

## Explicit non-claims

EvalIntegrityProof does not establish:

- that source declarations or external observations are true;
- semantic correctness of prompts, outputs, labels, scores, or rubrics;
- absence of every undiscovered leakage or sandbox escape technique;
- model safety, alignment, robustness, legal compliance, or fitness for use;
- identity or provenance of artifacts without a separate attestation; or
- authorization to run, release, procure, deploy, restart, or accept risk.

Use ProofRun when workflow provenance matters, ContainmentProof for harmless
runtime control exercises, and accountable human review for every consequential
decision.
