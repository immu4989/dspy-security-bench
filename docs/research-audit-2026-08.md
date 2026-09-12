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

## September 3 continuation: recovery readiness without an authority bypass

Multi-hop catch-up still depends on each old threshold being able to authorize
its exact successor. The TUF specification states that compromise of a root-key
threshold needs out-of-band recovery and is exceptionally difficult to make
safe. Automatically treating a different key set as trusted would erase the
continuity property this work is intended to protect.

[NIST SP 800-57 Part 1 Rev. 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5)
frames compromise recovery as a contingency-planning and key-management
problem: identify affected signatures, assess damage, define responsible
personnel and a re-key method, distribute replacement material, monitor the
operation, and prepare recovery instructions. It also highlights the tension
between redundant recovery material for continuity and the added compromise
surface created by more copies.

TrustRecoveryDrill converts that narrow preparedness question into an
AssuranceLedger artifact without defining a break-glass root replacement. The
current caller-anchored root must authorize the exact recovery-policy digest.
That policy binds five roles, actor/organization assignments, mandatory
custodian/approver separation, an organization-diversity floor, four response
windows, and maximum drill age. A simulation record then supplies nine fixed
stage types with timestamps and retained-evidence digests but no incident
narrative, key bytes, distribution address, or recovery instruction.

Thirteen deterministic checks preserve missing stages, role collapse,
organization concentration, evidence-class mismatch, root/policy mismatch,
future timestamps, response-window misses, and stale exercises as explicit
findings. `content_fields_processed`, `replacement_roots_activated`, and
`automatic_actions` remain zero. VerifierConformance v5 adds a rehashed recovery
summary mutation, while CapabilityManifest binds twelve offline protocols and
nineteen exact schemas. The result is drill evidence only; it cannot prove the
underlying records, identities, custody, facilities, communications, or actual
recovery capability, and cannot authorize any replacement root.

## September 3 continuation: authenticating recovery handoffs without reusing root authority

The tabletop layer made one important residual limitation explicit: its actor
and organization fields were owner assertions. A valid drill digest could prove
that those fields had not changed after construction, but not that the named
role key signed the event.

The [in-toto Statement v1
specification](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
provides a portable subject/predicate binding, while its [envelope
specification](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md)
recommends DSSE for serialization and authentication. The DSSE design signs a
pre-authentication encoding of both payload type and exact payload bytes, which
reduces cross-type confusion. In-toto's broader model also emphasizes evidence
of which step was performed, by which functionary, and in what order.

[NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
recommends informing people with recovery responsibilities about required
authorizations, verifying the integrity of restoration assets before use,
confirming restoration, and completing incident documentation. These are
operational goals rather than a wire protocol, but they motivate making role
handoffs and integrity checks independently inspectable.

TrustRecoveryAttestation applies those ideas narrowly. The existing recovery
policy remains the plan; a second exact policy maps dedicated Ed25519 public
keys to its assigned actors, roles, and organizations. AssuranceTrustRoot
authorizes both policy digests, but the event keys do not gain root-signing
authority. Each of the nine content-free events becomes an in-toto Statement
inside a DSSE envelope. Its predicate binds both policies, the root and drill,
the exact event and retained-evidence digest, the signer identity tuple,
issuance time, a unique nonce, and the preceding envelope digest.

Ten deterministic checks reject incomplete coverage, invalid envelopes,
changed subjects, context rebinding, role or key mismatch, bad signatures,
timestamp violations, replayed nonces, broken handoff chains, and missing root
authorization. VerifierConformance v6 adds a rehashed semantic mutation for the
new native verifier; CapabilityManifest now binds thirteen offline protocols
and twenty-two exact schemas. No content field is processed and no root is
activated. The result proves only that authorized keys signed exact simulated
records—not legal identity, competence, uncompromised custody, evidence truth,
real-world recovery, compliance, or operational authority.

## September 3 continuation: independently bounded time instead of one trusted integer

The trust-root, recovery, and evidence-freshness layers exposed a shared
assumption: their timestamps are evaluated against a caller-provided Unix
integer. That makes reproduction deterministic, but a rolled-back, isolated, or
incorrect clock can make expired authority appear current or move an event
across a response deadline.

[NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
SC-45 requires clock synchronization and includes enhancements for an
authoritative source and a secondary source in another geographic region.
[NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
notes that coordinated OT time supports accurate troubleshooting and forensics,
including cross-organizational correlation. These controls define operational
objectives, not a portable evidence format.

[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) requires a time-stamping
authority to use a trustworthy source, include a trustworthy time value and a
unique value, and bind the response to the requested message imprint. The
experimental [IETF Roughtime draft](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
signs a value derived from a client nonce and returns a midpoint with an
uncertainty radius. [TUF](https://theupdateframework.github.io/specification/latest/)
separately documents timestamp rollback and freeze checks, while acknowledging
that expiration bounds the remaining exposure.

AssuranceTimeQuorum takes a deliberately narrower, offline approach. An
independently pinned policy binds Ed25519 source keys, declared organizations,
minimum source and organization thresholds, a maximum per-source radius, and a
maximum final width. Each source signs the same artifact digest and verifier-
chosen nonce together with its identity, midpoint, radius, and exact derived
bounds. The analyzer never averages disagreement: it returns the maximum lower
bound and minimum upper bound, failing when the intersection is empty or too
wide.

Ten checks preserve policy replacement, artifact/nonce replay, source/key
substitution, bad signatures, radius manipulation, duplicate-source quorum
inflation, organization concentration, clock divergence, and excess uncertainty
as explicit evidence. At that milestone, VerifierConformance v7 added a rehashed
conservative-bound mutation, and CapabilityManifest bound fourteen offline
protocols to twenty-five exact schemas. The report processes zero artifact-content fields, makes
zero clock adjustments, and takes zero automatic actions.

This is not an RFC 3161, Roughtime, NTP, PTP, TSA, or clock-synchronization
implementation. It cannot prove UTC accuracy, source independence, source
security, legal identity, nonce freshness unless the verifier generated and
retained the nonce, or whether selected uncertainty limits are appropriate. Its
contribution is a deterministic bridge from independently signed rough-time
observations to the repo's portable assurance evidence boundary.

## September 4 continuation: time uncertainty must reach the trust decision

AssuranceTimeQuorum removed the unsupported assumption that one caller-supplied
integer represented trustworthy time, but it deliberately stopped at producing
an interval. A downstream caller could still discard that uncertainty, choose
the midpoint, and accept authority that was not valid for the complete interval.
That composition gap matters most at signed issuance and expiration boundaries.

TrustRootTimeGate makes the conservative rule executable. It first natively
recomputes the complete TimeQuorum report, rather than trusting its outer digest
or summary. It checks the independently retained policy digest and fresh nonce,
then requires the signed subject to equal the candidate root's exact digest.
Only after those prerequisites pass does it run the full AssuranceTrustRoot
evaluator twice: once at the maximum supported lower bound and once at the
minimum supported upper bound.

For AssuranceTrustRoot, validity over time is defined by the monotonic predicate
`issued_at <= evaluation_time < expires_at`. Therefore a passing evaluation at
both ordered endpoints establishes that temporal predicate throughout the
closed interval, while the full nested evaluations also repeat continuity,
signature-threshold, organization-threshold, domain, version, and policy-
authorization checks. The implementation explicitly does not generalize this
endpoint argument to arbitrary policy functions.

Eight deterministic checks keep invalid nested evidence, policy replacement,
nonce replay, subject rebinding, absent or unordered intervals, not-yet-valid
roots, expiry inside uncertainty, and other root-trust failures visible. The
strict artifact includes both endpoint reports so independent verifiers can
recompute the exact decision. VerifierConformance v8 adds a rehashed endpoint-
status mutation, and CapabilityManifest now binds fifteen offline protocols to
twenty-six exact schemas.

The gate makes zero network requests, adjusts zero clocks, installs zero roots,
and takes zero automatic actions. It does not prove UTC accuracy, actual source
independence, secure key custody, global root freshness, absence of a withheld
successor, compliance, certification, or authority to operate. Its narrower
contribution is to prevent independently signed uncertainty from disappearing
at the point where a trust anchor is accepted.

## September 5 continuation: independent evidence of root distribution

TrustRootChain can prove that a supplied sequence advances correctly, and
TrustRootTimeGate can prove the candidate remains valid across signed time
uncertainty. Neither can discover a newer root that a compromised, partitioned,
or stale distributor never supplies. That is a separate evidence problem from
cryptographic continuity.

The [TUF specification](https://theupdateframework.github.io/specification/latest/)
requires clients to update root metadata one version at a time and explicitly
describes freeze exposure when an attacker withholds newer metadata. The
[C2SP transparency-log witness protocol](https://c2sp.org/tlog-witness)
illustrates independent parties retaining and cosigning consistent checkpoint
advancement. The
[IETF Key Transparency Architecture](https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/)
discusses monitors, split views, third-party participation, gossip, and the
connectivity assumptions needed to expose forks. These sources motivate the
security property; RootViewQuorum does not claim compatibility or conformance
with any of them.

RootViewQuorum uses an independently retained policy of Ed25519 observer keys
and declared organizations. Each observer signs the verifier's exact candidate-
root digest, a fresh caller nonce, and the digest and version of the complete
root object it received. The root object is embedded so a standalone verifier
can recompute its digest and validate its current-root threshold rather than
trusting an observer-supplied label.

The analyzer classifies valid observations as matching, lagging,
same-version-conflicting, or newer. Only unique matching observers count toward
the observer and organization thresholds. Lag is preserved as distribution
telemetry. A same-version conflict or higher version is non-outvotable, so a
majority cannot erase evidence of a split or a candidate that may already be
stale.

Ten checks cover policy pinning and structure, candidate-root integrity and
domain, receipt shape, candidate/nonce binding, observer identity,
organization, key and signature, embedded-root recomputation, observer quorum,
organization diversity, and conflicting or higher roots. Three strict schemas,
policy and receipt CLI, exact offline report recomputation, SARIF, a fictional
three-organization demo, CI, and a rehashed v9 conformance mutation accompany
the protocol. CapabilityManifest now binds seventeen offline protocols to thirty-one
schema files, including eleven standalone verifiers.

The result deliberately remains narrower than “latest root.” It covers only the
selected observers and supplied responses. A higher-version observation does
not alone prove predecessor continuity. Declared organizations may not be
operationally independent, selected observers may all share a partition, and
undisclosed views remain invisible. The analyzer makes zero network requests,
installs zero roots, processes zero content fields, and takes zero automatic
actions. Its contribution is portable evidence at the boundary between valid
root metadata and its real-world distribution.

## September 5 continuation: reproducible RootView interoperability

A protocol with strict schemas and a Python reference verifier still leaves a
practical adoption gap: another implementation can parse the schema yet assign
different meaning to a nonce mismatch, duplicate observer, conflict, or
tampered derived summary. A prose contract alone does not reveal that drift.

The [TUF conformance suite](https://github.com/theupdateframework/tuf-conformance)
and [Sigstore conformance suite](https://github.com/sigstore/sigstore-conformance)
show the value of executing shared behavior across independent implementations.
[RFC 8032 section 7](https://www.rfc-editor.org/rfc/rfc8032.html#section-7)
provides deterministic Ed25519 known-answer inputs. These are design precedents,
not compatibility or certification claims.

The resulting RootViewQuorum v1 pack freezes 21 public input/report JSON files,
their exact SHA-256 digests, one immutable manifest, eight ordered inputs, seven
expected semantic results, and one
mandatory verifier rejection. Generation is byte-deterministic across
directories. The verifier checks an immutable official-manifest digest before
executing cases, so an edited and self-rehashed corpus cannot masquerade as v1.
Fixed signing seeds exist only as openly disclosed test material in generator
memory and temporary files; no private key is distributed in the pack.

This improves repeatable integration for agencies, suppliers, frontier labs,
and independent implementations without inflating the claim. Eight passing
cases cannot establish general conformance, parser safety, absence of other
state-machine defects, cryptographic-module validation, FIPS status,
certification, government endorsement, deployment approval, or an ATO.

## September 11 continuation: a genuinely independent vector executor

Publishing language-neutral JSON does not by itself establish language-neutral
behavior. If every passing result still comes from the Python reference
evaluator, canonicalization, signature, and state-machine mistakes can remain
shared across generation and verification.

The project therefore adds a second implementation in dependency-free Node.js.
It never imports or launches Python. The runner uses Node's native Ed25519
verification; the official
[`crypto.verify`](https://nodejs.org/api/crypto.html#cryptoverifyalgorithm-data-key-signature-callback)
contract specifies a `null` algorithm for Ed25519. It independently recomputes
the pinned manifest, 21 file digests, canonical object digests, embedded SPKI
key identities, root signature and organization thresholds, observer
signatures, nonce and candidate bindings, view classifications, quorum counts,
seven expected outcomes, and the mandatory rehashed-summary rejection.

The independent verifier was then extended from corpus execution to standalone
exact report recomputation across Ed25519, ECDSA P-256/SHA-256, and
RSA-PSS/SHA-256 roots. A differential suite makes 21 semantic changes, repairs
the outer report digest, and requires both implementations to reject every
case. The mutations span every summary value, findings, per-receipt results,
metadata, limitations, and an observer signature; simple hash checking cannot
pass the matrix.

This closes a concrete interoperability-evidence gap while keeping the claim
narrow. Both executors still consume the same finite corpus and specification;
agreement cannot prove general conformance, parser safety, independence of
their underlying cryptographic libraries, correctness on untested inputs,
FIPS validation, certification, government endorsement, deployment approval,
or an authorization to operate.

## September 11 continuation: privacy-minimized SLSA provenance import

SLSA provenance can describe output subjects, resolved build dependencies,
the build type, external parameters, and the builder identity. Those fields are
valuable supply-chain evidence, but copying their raw values into a portable
inventory can expose private repository names, artifact locations, workflow
parameters, or internal builder topology. The
[SLSA Provenance v1 predicate](https://slsa.dev/provenance/v1) also makes clear
that external parameters are untrusted input and that a builder identity names
the build platform's trust base; their presence alone does not prove that an
artifact is trustworthy. The
[in-toto Statement v1 specification](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
defines the envelope shape, while the
[ResourceDescriptor specification](https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md)
defines the subjects and dependencies being mapped.

AgentBOM SLSAImport v1 now converts a strict, unsigned in-toto Statement with a
SLSA Provenance v1 predicate into a deterministic, privacy-minimized AgentBOM.
It retains lowercase SHA-256 artifact digests and stable hashes of resource
identity, build type, and builder identity, but never copies raw names, URIs,
builder IDs, parameters, metadata, timestamps, byproducts, annotations,
embedded content, or extensions. A separate strict import report binds the
entire canonical source Statement and the exact derived AgentBOM so independent
consumers can recompute the transformation and detect edited, self-rehashed
reports. Stable identity hashes let a changed artifact digest appear as a
content change instead of a misleading remove-and-add event.

The boundary is deliberate: SLSAImport does not verify a DSSE envelope or
signature, establish a trusted builder, apply a caller's expectations, assign a
SLSA Build level, prove confidentiality, or endorse a supplier. Hashed
low-entropy identifiers can still be guessed. The report is import evidence,
not provenance authentication, certification, government endorsement,
deployment approval, or an authorization to operate.

## September 11 continuation: standards-native ML-BOM disclosure gaps

The generic CycloneDX importer could preserve a package graph, but it treated
AI-specific components as ordinary dependencies and copied raw names and
locators. That is a poor fit for cross-organization model review: the useful
question is often which disclosures exist and what changed, while model-card
text, dataset locations, sensitive-data labels, fairness descriptions, and
governance contacts can themselves be sensitive.

The official
[CycloneDX 1.7 JSON Schema](https://github.com/CycloneDX/specification/blob/1.7.1/schema/bom-1.7.schema.json)
defines first-class `machine-learning-model` and `data` component types. Its
model card covers learning approach, task, architecture, datasets, inputs,
outputs, performance analysis, intended users and uses, limitations, ethical
and environmental considerations, and fairness assessments. Component data can
describe contents, classification, sensitive data, graphics, description, and
governance. The related
[SPDX 3.0.1 AI profile](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/)
likewise treats models and datasets as distinct AI artifacts, reinforcing the
need for AI-aware inventory rather than package-only normalization.

AgentBOM MLBOMDisclosure v1 therefore maps CycloneDX 1.7 model and data
identities, dependencies, and model-to-dataset provenance into an incomplete
AgentBOM while emitting only field-presence gaps. It never copies raw disclosure
values. Identity is stable across content changes, the component digest binds
both declared artifact hash and complete source component, unresolved dataset
references remain visible, and the exact report can be recomputed only from the
separately retained source. The fictional input validates against the pinned
official CycloneDX 1.7.1 JSON Schema.

This is deliberately not an AI transparency score. Presence cannot establish
truth, adequacy, safety, fairness, privacy, provenance, license compliance, or
model quality. The mapper does not fully validate CycloneDX, authenticate its
signature, fetch artifacts, certify a model, approve a supplier or deployment,
or authorize operation. Deterministic hashes also do not protect low-entropy
source values from guessing.

## September 11 continuation: SPDX AI profile without semantic flattening

CycloneDX is not the only standards path for AI inventory. The
[SPDX 3.0.1 AIPackage](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/Classes/AIPackage/)
defines fifteen AI-specific properties spanning autonomy, domain, energy,
training, limitations, metrics, preprocessing, explainability, safety risk,
standards, model type, and sensitive personal information. The
[DatasetPackage](https://spdx.github.io/spdx-spec/v3.0.1/model/Dataset/Classes/DatasetPackage/)
defines dataset preparation, access, scale, intended use, bias, sensitivity,
and provenance-oriented fields. SPDX also defines explicit `trainedOn` and
`testedOn` relationship types rather than representing every data edge as a
generic dependency.

The AI and Dataset profile conformance rules each require exactly one
`hasDeclaredLicense` and exactly one `hasConcludedLicense` relationship per
package. SPDX's
[JSON-LD serialization guidance](https://spdx.github.io/spdx-spec/v3.0.1/serializations/)
requires the global 3.0.1 context and distinguishes structural JSON Schema
validation from semantic OWL/SHACL validation.

AgentBOM SPDXAIDisclosure v1 now preserves these distinctions in a separate
source-bound mapping. It records fifteen AI and thirteen dataset field-presence
gaps, retains counts for `trainedOn`, `testedOn`, `hasDataFile`, and `dependsOn`,
checks resolved exact-one license relationships without copying license values,
and maps stable model/dataset identities into an incomplete AgentBOM. The
fictional source passes the official SPDX 3.0.1 JSON Schema.

The mapper is not a JSON-LD processor and deliberately does not claim full SPDX
schema, OWL, SHACL, or profile conformance. Its license check is not legal
advice; field presence is not truth or adequacy; hashes are not confidentiality;
and the result is not model scoring, certification, government endorsement,
deployment approval, or an authorization to operate.

## September 12 continuation: cross-standard review without equivalence claims

CycloneDX 1.7 and SPDX 3.0.1 both describe AI models and datasets, but their
field structures differ. CycloneDX nests training, performance, limitations,
fairness, and environmental information in a model card. SPDX exposes separate
AI and Dataset profile properties and explicit relationship types. Treating
similarly named fields as interchangeable would discard meaning; copying values
into a central crosswalk would also expand the privacy boundary.

AgentBOM AIBOMCrosswalk v1 uses ten model and six dataset review topics only to
route human review. Before comparison it exactly reverifies both underlying
privacy-minimized reports against their retained sources. An owner must pair
components explicitly. Each topic distinguishes shared presence, shared
absence, one-sided presence, and the absence of a mapped field in one standard.
The report contains field names and privacy-hashed component IDs, never raw
values, and binds the two reports, sources, and pair policy by digest.

This design follows the distinct official
[CycloneDX model-card structure](https://github.com/CycloneDX/specification/blob/1.7.1/schema/bom-1.7.schema.json)
and [SPDX AI/Dataset model](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/)
without declaring compatibility. It does not compare hidden values, discover
component identity, prove semantic equivalence, rank standards or suppliers,
or make a compliance, procurement, certification, deployment, or ATO decision.

## September 12 continuation: owner-defined AI disclosure gates

Standards-native inventories make disclosure presence observable, but they do
not answer which disclosures a particular mission owner requires. Hard-coding
one universal checklist would confuse a tool author's preferences with agency,
sector, or enterprise risk ownership. It would also invite an attractive but
invalid aggregate score.

The official [CycloneDX ML-BOM capability description](https://cyclonedx.org/capabilities/mlbom/)
frames model and dataset transparency as input to informed deployment and
maintenance decisions. SPDX 3.0.1 separately defines exact-one declared and
concluded license relationships for both its
[AI profile](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/) and
[Dataset profile](https://spdx.github.io/spdx-spec/v3.0.1/model/Dataset/Dataset/).
NIST describes the AI RMF as voluntary and oriented toward organizations'
design, development, use, and evaluation practices; its Generative AI Profile
likewise proposes actions aligned with organizational goals and priorities.
These are design inputs, not claims that this feature implements NIST guidance
or establishes standards conformance.

AgentBOM AIDisclosurePolicy v1 therefore leaves the requirement set with a
named owner. It can require any field already represented by the privacy-
minimized CycloneDX/SPDX import reports, resolved AI/data references, and the
SPDX license-relationship shape. Before evaluation it exactly recomputes both
source-bound reports. Stable component-level findings distinguish missing
fields, unresolved references, and license relationship gaps and can be routed
through SARIF; an explicit flag, rather than a hidden default, decides whether
findings fail CI. The fictional profile intentionally fails four requirements.

No raw disclosure value enters the policy report, and no missing item is called
a vulnerability. A passing result means only that the owner-selected structural
requirements are present in the supplied reports. It cannot establish truth,
adequacy, freshness, safety, fairness, privacy, license compatibility,
compliance, supplier identity, certification, procurement or deployment
approval, risk acceptance, government endorsement, or an authorization to
operate. The evaluator grants no waiver and takes no automatic action.
