# Repository and evidence security model

## Trust boundaries

Model/provider execution is untrusted. Benchmark-owned environments observe
functional state. Report verifiers recompute outcomes and statistics. Submission
bundles content-address the verified report. GitHub/Sigstore attestations can
add builder and workflow identity, but do not independently observe a hosted
model provider.

AuthorityAdapter implementations are also untrusted. AuthorityTwin owns the
synthetic request/context and simulated effect trace, while the adapter supplies
an allow, deny, or review decision plus a narrowly normalized receipt. Receipt
hashes prove benchmark-internal consistency, not identity-provider signature,
execution authenticity, or non-repudiation.

FederalProof trusts only a verified source bundle plus an explicitly
owner-supplied deployment profile. Its manifest detects file changes, but an
authorized reviewer must still assess truthfulness, representativeness, linked
OSCAL documents, and the real deployment.

InventoryForge treats public inventory records as potentially stale secondary
evidence. It ignores contact fields and never promotes the record into
controlling policy. Generated packs contain a labeled synthetic policy and
remain drafts until an accountable owner reviews and versions them.

AgentGraphTwin composes the AuthorityAdapter trust boundary over a benchmark-
owned fictional path. Its first-unsafe-edge and blast-radius fields describe
the frozen synthetic graph only. AuthorityBridge fixtures test response
translation and never establish that a named backend, SDK, policy, credential,
or deployment was executed correctly.

ContinuousProof trusts only evidence types whose local verifier succeeds. It
detects digest, identity, and numeric-metric changes but does not monitor a
production system or decide whether a regression is acceptable.
AcquisitionProof trusts an owner-supplied profile and verified snapshot. Its
manifest preserves bytes, not the truth or completeness of owner declarations.

CollectiveGuard trusts only the supplied structural scenario. It rejects
application content fields, recomputes derived paths and response windows, and
binds the result to the scenario bytes. It cannot prove exporter completeness,
event authenticity, clock accuracy, production containment, or model alignment.

DefenderTwin trusts a frozen synthetic mission, its declared remediation
effects, and structural evidence-status labels. It independently recomputes
proposal bindings, attack-path closure, scope, approval timing, service
disruption, introduced risk, rollback, and evidence completeness. It never
executes the proposed change and cannot authenticate a declared evidence source
or establish production effectiveness.

ResilienceGraph trusts only locally verified DefenderTwin reports for candidate
eligibility, then performs exact arithmetic over owner-supplied services,
dependency edges, ordinal criticality, resource units, groups, constraints, and
availability scenarios. It keeps direct service coverage separate from
dependency reach, never infers a probability or financial benefit, and cannot
establish that the owner's planning assumptions are complete or true.

EvalIntegrityProof trusts operator-supplied content-free process observations.
It checks structural ordering, separation, monitoring, and accounting but cannot
authenticate telemetry, reveal omitted leakage, or establish evaluation truth.

AssuranceQuorum trusts a natively verified AssuranceGraph report plus an
owner-governed mapping from Ed25519 keys to declared signers, roles, and
organizations. DSSE verifies exact statements and key possession; it does not
prove human identity, employment, competence, independence, key revocation, or
decision authority. A satisfied quorum is review evidence, never approval.

AssuranceLedger trusts an owner-selected log operator, witness-key map, witness
threshold, and logged lifecycle declarations. It recomputes the full Merkle tree
and append-only prefix, but a bundled checkpoint cannot alone prove that no
other view was shown elsewhere. Witness signatures prove exact checkpoint
possession, not identity, independence, event truth, continuous monitoring, or
authority over the reviewed system. Retrospective `compromise_since` is a logged
governance declaration, not a compromise fact discovered by the analyzer.
AssuranceLedger Gossip reduces that blind spot only for supplied views: it
recomputes each source before exact-prefix comparison and treats two valid
operator-signed forks as equivocation evidence. It cannot detect a checkpoint
that no independent party obtained and shared.
AssuranceLedger ForkProof reduces a verified same-size conflict to its policy
and two signed checkpoints for offline incident sharing. It proves the disclosed
operator-key conflict and witness quorums, but omits the entries needed to say
which root represents a truthful history and does not automate notification or
remediation.
AssuranceLedger ConsistencyProof verifies the complementary positive claim: a
newer signed checkpoint preserves an older signed tree. Its minimal Merkle path
reveals no entry content, but the result is limited to the two disclosed
checkpoints and does not establish global dissemination or event truth.
AssuranceLedger ObserverReceipt trusts an owner-selected observer key map and
declared organization/channel policy. It authenticates what each key says it
observed and when, while hashing channel locators; it cannot prove that the
named organizations or channels are operationally independent.
AssuranceLedger WitnessConflict attributes signatures to embedded policy keys,
not people. A key that signs both fork views is cryptographically identifiable,
but the analyzer cannot distinguish compromise, implementation failure,
collusion, or other causes and performs no revocation.
AssuranceLedger VerifierConformance trusts the native verifiers it exercises;
v9 first requires sixteen clean source classes to pass native verification,
then demonstrates rejection of sixteen exact mutations—not the absence of other bugs.
Inputs and verifier code are identified by digest, and no network or system
action is performed.
AssuranceLedger RootViewQuorum trusts an independently retained observer-policy
digest, fresh caller nonce, observer keys, and declared organization mappings.
It proves only what the selected observers signed for that challenge. It cannot
discover undisclosed views, prove legal or operational independence, establish
global freshness, validate a complete successor chain from a higher-version
receipt, choose the truthful side of a conflict, or install a root.
Its v1 known-answer pack pins 21 exact public JSON artifacts through one
immutable manifest and carries eight expected
decisions; passing that finite corpus does not establish general conformance,
parser safety, cryptographic-module validation, implementation certification,
or an authorization to operate. Fixed generator seeds are public and test-only,
and no private-key file is emitted.
The companion Node.js runner is an independent implementation of the finite
vector semantics and uses no Python subprocess. Agreement between two
implementations reduces one class of shared-runtime error; it does not prove
that either implementation is defect-free or that untested inputs conform.
The differential suite covers 21 rehashed mutations and all three supported
trust-root signature schemes, but remains deterministic and finite.
AssuranceLedger CapabilityManifest trusts the package's compiled capability
table and local schema directory. Exact byte digests reveal drift, but do not
establish that a schema is secure, that another implementation is compatible,
or that a remote service actually offers the declared behavior.
AssuranceLedger IntegrationLock is unsigned and trusts the owner's source or
artifact governance to establish which lock was reviewed. It permits additive
capabilities and detects changed or missing pins; a satisfied check is not proof
that the owner approved the lock or that unpinned behavior is safe.
AssuranceTrustRoot replaces that implicit runtime trust assumption only when a
caller independently pins the first exact root digest or supplies a previously
trusted root. Dual old/new thresholds, exact successor versions, predecessor
digests, and expiration make unauthorized replacement, rollback, version gaps,
and possible freeze visible. They do not prove private-key custody, real
organizational independence, policy quality, post-quantum protection, or that a
newer root was not withheld before the current one expired.
AssuranceTrustRootChain extends that continuity across a bounded supplied
history. It intentionally accepts expired roots only as verified historical
links and requires the final root to be current. It cannot discover a withheld
newer root, so deployments need an independently governed minimum-version or
freshness signal when truncation matters.
TrustRecoveryDrill trusts owner-supplied content-free event metadata and
digests. It verifies that the exact root-authorized plan was exercised with the
declared roles, separation, organization diversity, stages, ordering, response
windows, and freshness; it cannot prove the retained evidence is truthful or
that recovery will succeed. The protocol deliberately cannot activate or
authorize a replacement root.
TrustRecoveryAttestation reduces that actor-assertion gap by requiring every
event to carry a DSSE signature from a dedicated key in an exact root-authorized
attester policy. It proves possession of those keys over exact in-toto
statement bytes and detects missing, reordered, or replayed handoffs within the
supplied chain. It cannot prove human identity, competence, key custody,
underlying evidence truth, or real-world recovery, and it grants no root
authority.
AssuranceTimeQuorum trusts an independently distributed policy digest, fresh
caller nonce, and the clocks and keys behind its selected sources. It verifies
that distinct declared organizations signed overlapping bounded intervals for
one artifact, but cannot prove source independence, UTC accuracy, clock
discipline, nonce freshness unless retained by the caller, or key custody. It
returns an interval and never adjusts a system clock.
TrustRootTimeGate inherits those assumptions plus the complete AssuranceTrustRoot
boundary. It verifies that the time evidence names the exact candidate root and
that the root passes at both conservative endpoints; it cannot establish UTC
accuracy, source independence, global root freshness, or absence of a withheld
successor. The endpoint argument is valid only for the root evaluator's
monotonic issuance and expiration predicates, not arbitrary time-dependent
policy logic. It installs no root and takes no automatic action.

## Threats addressed

- narrative-only scores hiding harmful tool side effects;
- modified summaries that disagree with nested action traces;
- unstable stochastic outcomes hidden by one successful run;
- evidence or policy files altered after evaluation;
- reference fixtures presented as model measurements;
- ambient credentials, identity substitution, scope/tenant/audience confusion,
  revoked or replayed authority, delegation inflation, and intent mismatch made
  invisible by clean task-success metrics;
- control mappings presented as automated compliance; and
- release supply-chain drift through unpinned GitHub Actions.
- contact data unintentionally copied from a public AI inventory into a test
  pack;
- authorization failures hidden inside a successful multi-agent terminal
  outcome;
- metric or protocol drift hidden by replacing a benchmark screenshot; and
- missing acquisition cost or outcome observations silently treated as passes.
- unapproved cross-run side channels, indirect egress, peer instructions treated
  as authority, cross-run credentials, evaluator access, unsafe persistence,
  late escalation/containment, unapproved restart, and correlated defenses; and
- remediations that appear effective while exceeding authority, breaking an
  essential service, introducing new declared risk, losing rollback, or relying
  on incomplete evidence; and
- unsafe remediations entering a resource plan, dominated portfolios presented
  as efficient, impossible owner floors silently relaxed, or a deterministic
  tie-break mislabeled as a funding recommendation.
- holdouts revealed before result commitment, shared evaluator/workload trust
  domains, unaccounted cases, blind monitors, and unsafe evaluation continuation;
  and
- one signature presented as multi-disciplinary review, role/key substitution,
  duplicate-signer quorum inflation, outvoted evidence gaps, stale review
  statements, or signatures replayed against a different report or policy.
- self-signed replacement trust roots, single-sided key rotation, root rollback,
  skipped rotation history, expired trust, undeclared algorithm changes, and
  same-name/different-byte assurance policies presented as authorized.
- one caller-controlled timestamp presented as corroborated time, time receipts
  replayed against another artifact or challenge, one source duplicated into a
  quorum, silently divergent clocks, or uncertainty averaged away.

## Threats not solved

- a malicious provider or evaluator fabricating the entire interaction trace;
- compromised runners, dependencies, maintainers, or signing identities;
- production-only behavior, distribution shift, insider abuse, or novel attacks;
- privacy, civil-rights, records, accessibility, legal, or mission authorization;
- safe integration with live operational tools;
- real token/key custody, identity proofing, authorization-service correctness,
  revocation latency, cryptographic provider receipts, or non-repudiation; and
- long-term availability of third-party services.
- completeness or currency of public inventories, mission-owner approval,
  procurement authority, price reasonableness, vendor portability, or the
  representativeness of a generated mission draft; and
- asynchronous graph races, graph-wide production blast radius, backend policy
  semantics beyond the normalized bridge contract, or continuous production
  telemetry.
- omitted collective events, covert channels without a shared structural
  identifier, fabricated offsets, or assurance that an observed response action
  had its intended production effect; and
- unmodeled attack paths, incorrect synthetic remediation effects, fabricated
  source-completeness labels, live-system exploitability, or safe production
  rollout of a DefenderTwin proposal; and
- omitted infrastructure dependencies, inaccurate service mappings, real-world
  availability probabilities, monetary loss, distributional impacts, supplier
  ownership, or the correctness of a ResilienceGraph planning contract.
- reviewer identity proofing, organizational independence, competence, key
  custody/rotation/revocation, or legal authority to approve, procure, deploy,
  authorize operation, or accept risk.

Use least privilege, protected branches, required reviews, secret scanning,
artifact attestations, dependency review, CodeQL, Scorecard, SBOMs, reproducible
verification, and independent reproduction as complementary controls.
