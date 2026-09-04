# Research and repository audit — August 2026

This note records why the next contribution focused on actionable evidence and
benchmark integrity instead of adding another broad attack-success benchmark.
It is a dated prioritization record, not an exhaustive systematic review.

## Evidence reviewed

- [NIST AI 800-5](https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai)
  reports broad agreement that agent-security concerns impede adoption and that
  existing cybersecurity practices need adaptation.
- [NIST evaluation probes](https://www.nist.gov/programs-projects/building-evaluation-probes-agentic-ai)
  call for increased visibility into tool usage and machine-readable audit
  trails that connect agent decisions to evidence.
- [MPBench](https://arxiv.org/abs/2606.04329),
  [stored prompt injection](https://arxiv.org/abs/2606.04425), and
  [Bad Memory](https://arxiv.org/abs/2607.14611) already provide substantial
  2026 coverage of memory poisoning and cross-session persistence.
- [Counterfactual Trace Auditing](https://arxiv.org/abs/2605.11946) shows why
  paired traces reveal behavioral changes hidden by endpoint pass rates.
- [ContainmentBench](https://arxiv.org/abs/2607.23999) separately measures
  terminal outcomes, trace propagation, recovery evidence, and useful action.

## Repository audit

The repository already measured functional end state, but users still had to
manually reconstruct where a clean/poisoned execution diverged and which policy
boundary could contain it. Three integrity problems were also visible:

1. the public CI matrix was red on Python 3.10 and 3.11 because resource tests
   relied on newer `Traversable.joinpath` behavior; and
2. open issue #2 demonstrated that newline- and tab-separated payloads passed
   through `spotlight_datamark` without a single marker; and
3. CI, Pages, and release workflows used mutable, outdated action tags, leaving
   a security-focused project with avoidable supply-chain drift and Node 20
   deprecation warnings.

A new generic memory benchmark would therefore duplicate fast-moving work while
leaving immediate trust and usability gaps unresolved.

## Selected contribution

**BoundaryDiff** adds environment-owned action traces to ImpactTwin, locates the
first event-level divergence, reports poisoned-only events and functionally
observed harms, and maps the failure to an executable rule in the packaged
procurement policy. Saved schema-v3 reports can be explained offline.

Acceptance criteria:

- scoring never depends on a model's self-reported trace;
- all five vulnerable fixtures produce a localized divergence and applicable
  control, while all bounded twins remain trace-equivalent;
- JSON schema and SARIF preserve the new evidence;
- stochastic single-pair limitations are explicit;
- Python 3.10–3.14 tests pass; and
- multiline datamarking is mechanically regression-tested.

The repository workflows are also upgraded to current Node 24 action releases,
pinned by full commit SHA, with a fixed uv version for repeatable CI setup. The
matrix covers Python 3.10–3.14 without installing the optional PyTorch-based
synthesis stack in every job.

This work does not claim that trace auditing, counterfactual comparison, memory
security, or least privilege is individually novel. Its value is an integrated,
reproducible path from public-interest failure to inspectable evidence and a
deployable authority boundary.

## Follow-on: repeated-execution evidence

The August 12 follow-on addresses the audit's remaining statistical limitation:
a single paired run cannot establish stable behavior for a stochastic agent.
RepeatTwin retains multiple complete trials, reports Wilson score intervals for
each fixed attack pair and the aggregate fixed suite, exposes outcome-class
instability and runtime errors, and preserves optional provider token/cost
telemetry. The sampling unit is declared as `fixed_suite_pair_trial`; no claim
is made that five frozen scenarios represent an unseen procurement-task
population.

Community bundles add recomputable statistics and canonical content hashes.
They are deliberately labeled self-attested: tamper evidence is not execution
provenance. This follows the same trust-boundary discipline as BoundaryDiff—say
exactly which evidence the system owns, and do not silently upgrade a checksum
into a stronger claim.

## Follow-on: ProofRun provenance

A second landscape check reviewed contemporary prompt-injection evaluation
platforms including [PIArena](https://github.com/sleeepeer/PIArena), benchmark
reproducibility work such as
[redharness](https://github.com/MohamedAklamaash/redharness), NIST's call for
machine-readable agent-evaluation audit trails, GitHub artifact attestations,
and the [SLSA v1.2 verification model](https://slsa.dev/spec/v1.2/verifying-artifacts).
The reviewed benchmark projects preserve configurations, transcripts, or
content-addressed evidence. This dated, non-systematic search did not identify a
prompt-injection benchmark that also provides all of the following as one
contribution path:

- repeated counterfactual agent trials with an explicit estimand and confidence
  lower-bound gate;
- offline recomputation from preserved raw functional outcomes;
- an in-toto/Sigstore attestation over the exact result artifact;
- verifier policy for repository, commit, ref, hosted runner, and signer
  workflow; and
- distinct public tiers for content integrity, caller-workflow provenance,
  central-builder provenance, and independent reproduction.

ProofRun implements that integration without claiming that its ingredients are
individually novel. The trusted workflow separates the untrusted evaluation job
from a clean verification/signing job: provider credentials are available only
to evaluation, while OIDC signing authority is available only after the frozen
engine recomputes the downloaded bundle. This follows SLSA's core separation
between a tenant-controlled process and the control plane that records
provenance.

The boundary remains explicit. A valid attestation proves that a named workflow
produced exact bytes from a named source commit. It cannot prove that a remote
provider returned the embedded response, that evaluated source code is honest,
or that five synthetic procurement pairs establish deployment safety. The
dashboard therefore requires a reviewed, digest-keyed registry before showing a
cryptographic tier; an unverified provenance claim is displayed as pending.

## Follow-on: ControlTwin policy efficacy

An August 13 landscape refresh reviewed NIST's tool-use taxonomy and 2026 agent
identity/authorization concept paper, the OWASP Top 10 for Agentic Applications,
MCP's clarification that tool annotations are hints rather than enforcement,
and contemporary static agent scanners, authority manifests, runtime policy
engines, and least-privilege research.

The practical gap was no longer “list the tools” or “write a deny rule.” The
repository itself already had an executable policy engine and BoundaryDiff could
recommend its rules. What users still could not demonstrate was whether applying
that policy changed a functional outcome, whether the agent recovered the useful
mission after a denial, or whether the control broke clean work.

ControlTwin therefore runs the frozen ProcureBench protocol in two conditions:
raw agent and policy-wrapped agent. It retains both complete ImpactTwin reports,
adds benchmark-owned policy-boundary decisions, hashes the normalized policy,
and independently reports:

- prohibited functional outcomes before and after control;
- synthetic scenario exposure before and after control;
- attack resistance and safe mission recovery;
- clean and poisoned mission utility;
- residual harms, introduced harms, and recovery gaps; and
- offline-recomputable aggregates plus GitHub SARIF.

The deterministic reference closes every observed harmful side effect and
reduces synthetic exposure from $3.69M to $0 without clean-utility loss. It only
recovers three of five attacked missions. Publishing both facts prevents a
deny-all boundary from being mislabeled as a complete agent-security solution.

This work does not claim that policy engines, A/B evaluation, least privilege,
or functional security testing are individually novel. The contribution is the
integrated, falsifiable loop from controlled prompt-injection failure, to an
executable boundary, to policy-off/policy-on functional and mission evidence,
to a policy-hash-bound report that can be recomputed offline.

## Follow-on: RepeatControlTwin paired uncertainty

The next implementation closes ControlTwin's single-run limitation. It repeats
the full paired experiment, gives every case and condition a fresh agent, and
alternates which condition runs first. It preserves all child evidence and
reports transition-conditional Wilson score intervals, per-pair effect
stability, and the exact two-sided McNemar test over prevented versus introduced
functional harms.

The statistical design is intentionally legible. Conditional rates name their
observed denominator—such as baseline-harmful, baseline-failed, baseline-clean-
successful, or contained pair-trials—and become unavailable rather than zero
when no eligible observation exists. The exact paired test avoids a large-
sample approximation. Newcombe's 1998 analysis of paired binary-proportion
intervals informs the interpretation boundary; this version does not claim to
implement Newcombe's full paired-difference interval.

Robert G. Newcombe, “Improved confidence intervals for the difference between
binomial proportions based on paired data,” *Statistics in Medicine* 17 (1998),
2635–2650. [DOI](https://doi.org/10.1002/(SICI)1097-0258(19981130)17:22%3C2635::AID-SIM954%3E3.0.CO;2-C).

RepeatControlTwin still does not infer performance on unseen tasks. Its
sampling unit is one fixed ProcureBench pair in one trial, and its intervals
quantify execution variability for those five synthetic pairs under the tested
agent, policy, provider, and protocol identities. Alternating order reduces one
systematic bias; it does not remove provider drift, deployment mismatch, or
unobserved attack paths. The nominal Wilson and McNemar calculations also treat
pair-trial executions as exchangeable. Shared provider conditions can correlate
cases, so the raw trials and per-pair stability remain part of the evidence
rather than being discarded behind a p-value.

## Follow-on: ScheduleProof bounded authorization interleavings

The August 27 landscape refresh reviewed the NIST AI Agent Standards
Initiative, NCCoE's 2026 software and AI agent identity/authorization concept
paper, NIST's evaluation-probe work, the draft NIST TEVV-Athlon framework, and
the stable MCP 2025-11-25 authorization and Tasks specifications. Together they
reinforce a practical need for interoperable authorization evidence,
machine-readable verification, explicit test boundaries, resource/audience
binding, and authorization-context continuity. AgentGraphTwin v2 covered six
fixed temporal examples, but it could not answer a different question: which
other event schedules remain valid when a real design guarantees only a partial
order?

ScheduleProof makes that gap falsifiable. A strict data-only scenario declares
typed grant, revoke, approval, token-exchange, and effect events plus only the
happens-before edges the operator says are enforced. A deterministic explorer
computes the exact number of reachable topological schedules, visits every one
up to a declared bound, checks eight execution-boundary invariants, and retains
the shortest counterexample prefix and causal slice for each failure class.
Truncation without a finding becomes `incomplete_review`, never safe. The
unsafe-schedule fraction is explicitly a schedule-space ratio and not a
production probability.

The work does not claim that model checking, topological exploration,
authorization logic, or concurrency testing is individually novel, and this
dated review is not sufficient to substantiate a global-first claim. The
research contribution is their integration into a content-addressed
agent-authorization protocol with strict denial-of-service bounds, SARIF,
ContinuousProof identity, and full offline semantic recomputation. The main
validity threat remains model adequacy: omitted events, false ordering edges,
non-atomic operations, network failure, or weak-memory behavior can make a
complete bounded result irrelevant to production.

## Follow-on: EvalIntegrityProof evaluator-compromise evidence

An August 30 review of NIST's
[agentic evaluation-probe program](https://www.nist.gov/programs-projects/building-evaluation-probes-agentic-ai)
and OpenAI's
[Hugging Face incident analysis](https://openai.com/index/hugging-face-incident-and-the-road-ahead/)
identified a different trust boundary: a benchmark can have good tasks and
correct statistics while the evaluator, hidden labels, credentials, or result
publication path is compromised. A model score alone cannot reveal that
failure.

EvalIntegrityProof encodes 13 mechanically checkable evaluation-process
controls, including precommitted holdout identity, result-before-label-reveal
ordering, evaluator/data isolation, credential and network separation, case
accounting, leakage canaries, an independent monitor, safe exit, minimization,
and clock integrity. It distinguishes evidenced integrity, observed violation,
monitor failure, and incomplete evidence. This is process evidence, not a claim
that an evaluated model is safe or that the recorded events are externally
true. The integration into AssuranceGraph makes evaluator integrity a required
claim rather than an unstructured paragraph beside a model score.

The implementation does not claim that canaries, holdouts, isolation, or
independent monitoring are individually novel. The contribution is a strict,
content-addressed, offline-recomputable evidence protocol that keeps a broken
monitor separate from an observed evaluation violation and refuses to translate
missing evidence into success.

## Follow-on: AssuranceQuorum role-separated review evidence

The same-day follow-on reviewed the official [in-toto Statement
v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) and
[DSSE envelope](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md)
specifications, [SLSA v1.2 artifact
verification](https://slsa.dev/spec/v1.2/verifying-artifacts), and
[Sigstore bundles](https://docs.sigstore.dev/about/bundle/). These standards
provide strong interoperable building blocks, but they deliberately leave the
consumer's trust policy to the verifier. AssuranceGraph previously had one
accountable owner but no portable way to demonstrate that evidence was reviewed
by separately governed functions.

AssuranceQuorum adds policy-authorized Ed25519 reviewers, role- and
claim-scoped in-toto statements, DSSE signatures, bounded review windows, and
minimum distinct-organization requirements. A valid assigned
`evidence-gap` statement is a veto and cannot be erased by additional supporting
signatures. Impossible organizational quorums fail during policy validation.
The four outcomes keep satisfied, incomplete, gap-recorded, and invalid review
evidence distinct.

This work does not claim that multisignature approval, separation of duties,
in-toto, DSSE, or Ed25519 is individually novel. Its narrower contribution is
the integration of role-separated review with natively recomputed AI-assurance
claims while explicitly withholding deployment, ATO, procurement, compliance,
and risk-acceptance authority. Declared role and organization identifiers are
policy assertions; identity proofing, key custody, rotation, and revocation
remain external and motivate a future trust-registry adapter.

## Follow-on: AssuranceLedger witnessed reviewer-key lifecycle

AssuranceQuorum made its next trust gap explicit: an Ed25519 signature can
remain mathematically valid after a credential is retired or discovered to have
been compromised. A single log operator can also present different histories
unless checkpoints are compared outside its trust domain. The follow-on review
used the append-only Merkle and audit model in [RFC
6962](https://www.rfc-editor.org/rfc/rfc6962) and [RFC
9162](https://www.rfc-editor.org/rfc/rfc9162), the consistency-before-cosigning
model in the [C2SP transparency-log witness
protocol](https://c2sp.org/tlog-witness), Sigstore's portable inclusion-proof
and trust-root direction, and TUF's explicit key-threshold and rotation model.

AssuranceLedger integrates a strict reviewer-key registration, exact review
envelope logging, retirement/compromise events, RFC 6962-style domain-separated
Merkle roots, operator-signed checkpoints, distinct-organization witness
thresholds, per-review inclusion paths, and append-only prefix recomputation.
Historical retirement and retrospective compromise have different outcomes: a
retired key can preserve a review's historical validity, while a logged
`compromise_since` at or before signing invalidates it.

This work does not claim that transparency logs, Merkle trees, witnesses,
revocation, or threshold trust are individually novel. It is not a CT, Rekor,
C2SP, or TUF wire implementation. The narrower contribution is their
self-contained application to natively recomputed, role-separated AI-assurance
review evidence with explicit non-authority semantics. A bundle can prove its
own tree and prefix but not the absence of a split view elsewhere; deployments
must exchange checkpoint roots across independent channels to gain that
detection property.

The next loop implements that comparison as AssuranceLedger Gossip. It first
natively verifies each complete ledger view, then compares every checkpoint
pair under one origin and policy. Exact prefixes are consistent extensions;
same-size signed checkpoints with different roots, or a divergent smaller
history, become equivocation evidence. Repeated copies of one checkpoint remain
insufficient diversity, and an invalid view cannot become fork evidence. This
implements the bounded, offline form of RFC 6962's checkpoint-gossip principle
without claiming that supplied files represent every view in circulation.

The resulting lifecycle evidence exposed an operational efficiency problem:
organizations should not have to repeat every review after one reviewer-key
incident. AssuranceLedger ReReview therefore recomputes the ledger and projects
each non-current review through the frozen AssuranceQuorum claim assignments.
It produces the minimal affected claim/role set, preserves evidence-gap vetoes,
and binds an explicit owner choice for routine historical keys. This is aligned
informatively with the NIST AI RMF Core's ongoing monitoring, periodic review,
defined roles, and change-management themes; it neither implements the AI RMF
nor automates the accountable decision.

The gossip result also exposed a disclosure tension: a complete proof bundle is
auditable but can reveal reviewer and lifecycle metadata irrelevant to proving
a same-size fork. RFC 6962 states that two conflicting signed tree heads from
one log are cryptographic evidence of misbehavior, while C2SP witnesses cosign
exact checkpoints only after consistency verification. AssuranceLedger
ForkProof therefore exports only the policy, two signed checkpoints, and source
digests. Its standalone verifier checks both operator signatures and witness
quorums, same log identity and size, and different roots. It includes no log
entry, reviewer registration, review envelope, or quorum report, and it does not
claim which history is truthful or automate incident response.

The symmetric privacy need is proving legitimate growth without releasing the
new entries. RFC 6962 defines a unique minimal consistency path, and RFC 9162
specifies how the same path reconstructs the older and newer roots.
AssuranceLedger ConsistencyProof generates that path only after natively
verifying both full source reports and their exact prefix. The portable
verifier then needs only the policy, two signed checkpoints, and Merkle nodes;
it rechecks both operator signatures, both witness quorums, and both roots while
embedding zero log or review entries. The result proves only the disclosed extension, not global
consistency or event truth.

Finally, source-report hashes did not establish who independently received each
checkpoint. The IETF SCITT architecture (RFC 9943) uses signed receipts as
portable, offline-verifiable proofs and permits hashes in place of large or
sensitive statements. AssuranceLedger ObserverReceipt applies that design
direction—without claiming COSE/SCITT compatibility—to checkpoint exchange.
Policy-authorized observers sign the exact checkpoint, source digest,
observation time, declared channel class, and a hash of the private channel
locator. Cross-view analysis requires distinct observer keys, declared
organizations, and channel hashes before labeling a fork independently
observed. These are authenticated declarations, not external proof of
organizational independence.

The reference fork also demonstrated that “operator equivocation” can hide a
second accountability question: did any witness key cosign both roots? The C2SP
witness protocol requires rejecting a same-size checkpoint whose root differs
from the witness's stored checkpoint. AssuranceLedger WitnessConflict therefore
verifies ForkProof first and intersects exact witness signer/key pairs across
both views. This produces key-level evidence without assigning a human actor,
inferring motive or compromise cause, or automatically notifying or revoking.

The growing portable surface then created an adoption risk: downstream
implementations could validate the outer hash while failing to recompute deeper
semantics. AssuranceLedger VerifierConformance v3 applies ten deterministic
mutations, rehashes every mutated report, and requires a specific rejection from
the ledger, gossip, re-review, ForkProof, ConsistencyProof, ObserverReceipt, and
WitnessConflict, CapabilityManifest, and IntegrationLockCheck verifiers. The
matrix binds its source digests and can be rerun
offline. Its scope is deliberately finite and is not described as fuzzing,
certification, or proof of verifier security.

V2 converted clean-fixture validity from prose into an experimental
invariant. V3 requires all ten source artifact classes to pass their native verifier before
mutation; one invalid source aborts the run. This prevents an unrelated existing
failure from being miscounted as evidence that a deliberate mutation was caught.

The conformance matrix then exposed a different integration failure mode:
partner code could support the right report names but validate them against an
old or locally modified schema. JSON Schema Draft 2020-12 gives schemas stable
`$id` identifiers and an explicit dialect, but neither identifies the exact
bytes shipped by one implementation. AssuranceLedger CapabilityManifest adds a
deterministic catalog of all fifteen local schema IDs and file digests, then maps
ten protocol versions to their production and verification commands,
standalone/evidence-root requirements, disclosed data classes, offline boundary,
and zero automatic actions. Reverification recomputes both the capability table
and every schema digest, so a replacement outer hash cannot hide semantic or
schema drift.

The design review also considered RFC 8615 origin metadata. That RFC requires a
registered, application-specific suffix and explicit scoping, so this repository
does not squat on a generic `/.well-known/` name or imply remote discovery.
CapabilityManifest is intentionally a local integration contract and not a
service-authentication or interoperability-certification mechanism.

Finally, discovery alone does not let an adopter distinguish an intentional
upgrade from an unreviewed compatibility regression. IntegrationLock converts a
locally verified manifest into an owner-pinned minimum: all schema digests plus
the report identity, verifier command, portability boundary, disclosed data
classes, and action count for each required protocol. Candidate checks allow
additions but report missing or changed pins and recompute from the exact lock,
manifest, and local schemas. The unsigned lock is explicitly not approval
evidence; owner-controlled source or artifact governance remains the trust root.

## September 3 follow-on: AssuranceTrustRoot continuity and algorithm migration

IntegrationLock made the remaining circular assumption visible: source control
was called the trust root, but the ledger family had no portable way to express
which root keys and exact policies a verifier should accept, when that trust
expires, or how a new key set becomes authoritative. A replacement JSON file
could be perfectly self-signed by replacement keys and still provide no
continuity from a verifier's previously accepted state.

The follow-on review used The Update Framework's root-update workflow, which
requires every intermediate root and signatures satisfying both the previously
trusted and candidate root thresholds. It also used the June 2026 update to
[NIST CSWP 39, Considerations for Achieving Crypto Agility](https://doi.org/10.6028/NIST.CSWP.39-upd1),
which emphasizes explicit algorithm identifiers, planned transitions, and
integrity protection for algorithm change. The finalized [SCITT architecture,
RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html), separately reinforces
that trust anchors and registration policy are explicit inputs to transparent
signed-statement systems.

AssuranceTrustRoot integrates those design properties into an AssuranceLedger-
specific, offline format. The first root remains untrusted unless the caller
supplies its exact digest through an independent channel. A successor must be
exactly version `N+1`, name the full digest of root `N`, remain unexpired, and
satisfy both old and new key and distinct-organization thresholds over the same
canonical payload. The signed root authorizes exact AssuranceLedger,
ObserverReceipt, and AssuranceQuorum policy digests and identifies Ed25519,
ECDSA P-256/SHA-256, or RSA-PSS/SHA-256 keys. The report distinguishes invalid
evidence, untrusted bootstrap, expiration, rollback, skipped versions,
continuity failure, unauthorized policy, trusted bootstrap, and trusted
rotation rather than blending them into one boolean.

This work does not claim that threshold signatures, trust roots, expiration,
key rotation, or algorithm identifiers are individually novel. Its contribution
is a strict, semantically recomputable bridge between those controls and the
repo's AI-assurance evidence policies, including exact policy authorization and
old/new organization thresholds. It is not TUF or SCITT compatible, does not
provide post-quantum signatures, cannot prove private-key custody or real
organizational independence, and takes no operational action. The v3
conformance matrix adds a rehashed TrustRoot signature mutation so downstream
implementations must exercise the deeper cryptographic verifier rather than
accepting a replacement outer digest.

## September 3 continuation: bounded stale-client root catch-up

The first TrustRoot increment made a second gap explicit: a verifier that was
offline for two rotations cannot safely skip from root `N` to root `N+2`.
Accepting only the latest self-threshold would discard the old authority;
requiring root `N` to sign `N+2` would discard the authority that root `N+1`
legitimately introduced.

The [TUF root-update workflow](https://theupdateframework.github.io/specification/latest/#update-root)
requires outdated clients to retrieve every intermediate root, advance exactly
one version at a time, and validate each candidate under both its immediate
predecessor threshold and its own threshold. It defers the expiration decision
until the latest supplied root, allowing an expired historical root to remain a
continuity link. This is particularly relevant to the long-lived systems called
out in the joint [CISA secure-by-demand guidance for operational technology](https://www.cisa.gov/sites/default/files/2025-01/joint-guide-secure-by-demand-priority-considerations-for-ot-owners-and-operators-508c.pdf),
while NIST CSWP 39upd1 frames algorithm replacement without unnecessary
operational disruption as enterprise crypto agility.

AssuranceTrustRootChain implements that narrow security property as an offline,
AssuranceLedger-specific report. It accepts either a locally persisted trusted
root plus its successors or a chain whose first exact digest was distributed
independently. Up to 64 roots are checked in order. Every hop records exact
version/digest continuity, old/new key and declared-organization threshold
counts, source errors, and algorithm additions/removals. Expired intermediates
are disclosed but accepted only as historical links; the final root must be
issued, unexpired, and authorize the exact supplied policy digests.

An offline verifier cannot know that a distributor withheld root `N+1` when it
is shown a valid root `N`. The caller-controlled `minimum_final_version` is
therefore part of the report rather than an inferred freshness claim. It can
turn a known truncated prefix into `final_version_not_reached`, but the source
of that version floor remains deployment-owned. The v4 conformance matrix adds
a rehashed chain-hop mutation, and CapabilityManifest now binds eleven protocol
contracts to sixteen exact schemas. None of those artifacts retrieve metadata,
approve an update, prove key custody, establish legal identity, or take an
operational action.
