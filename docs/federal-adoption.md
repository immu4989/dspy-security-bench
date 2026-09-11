# Federal and regulated-enterprise adoption path

This guide describes a practical pilot path. It is not legal, acquisition,
privacy, civil-rights, accessibility, cybersecurity, or authorization advice.

## Phase 0 — choose a bounded mission

Start with an advisory workflow whose outputs receive human review. Name the
affected people, intended benefit, disallowed outcomes, data boundary, tool
authority, appeal/remedy path, and an accountable system and risk owner. Do not
begin with autonomous irreversible action.

When a public AI use-case inventory already describes the mission, use it as a
starting signal—not policy authority:

```bash
dspy-security-bench inventory import public-ai-inventory.csv --out inventory.json
dspy-security-bench inventory draft-pack inventory.json USE-CASE-ID --out mission-pack.yaml
```

InventoryForge removes contact fields and labels the result as a synthetic
draft. The accountable mission owner must replace assumptions and approve the
test contract.

## Phase 1 — establish evidence requirements

Use measurable outcomes rather than vendor architecture preferences. Require a
frozen agency-controlled evaluation set, exact model/system configuration,
repeat trials, error accounting, cost/latency evidence, change notification,
data-use disclosure, logs, portability, and re-evaluation rights. Keep a portion
of evaluation data undisclosed to the vendor.

The generated QASP is a drafting input. Contracting officials must tailor it to
the acquisition and the current FAR, including [performance-based acquisition](https://www.acquisition.gov/far/subpart-37.6)
and [government contract quality assurance](https://www.acquisition.gov/far/part-46).

## Phase 2 — run synthetic twins before production data

1. Run AuthorityTwin against the proposed identity/authorization adapter to
   test principal-agent binding, least privilege, revocation, intent, approvals,
   audience, tenant, delegation, and audit handling.
2. Run AgentGraphTwin to locate identity, scope, tenant, revocation, approval,
   and intent failures across the human-to-agent-to-tool path.
3. Run ImpactTwin for procurement decision and economic-integrity failures.
4. Run IncidentTwin for cyber-response side effects and approval boundaries.
5. Run CollectiveGuard against a synthetic structural record to test cross-run
   isolation, egress, safe-stop, evaluator integrity, response windows, restart
   approval, and independent containment controls.
6. Run SourceTwin for traceable grounding, material-exception retention,
   current-primary preference, and correct abstention.
7. Use MissionForge to encode owner-reviewed synthetic claims and sources while
   keeping an evaluation set unavailable to the vendor.
8. Run ControlTwin/RepeatControlTwin to show that the proposed policy changes
   functional outcomes without destroying clean utility.
9. Run EvalIntegrityProof to preserve holdout commit/reveal ordering, evaluator
   separation, complete case accounting, monitoring, and safe-exit evidence.
10. Retain every raw trial and runtime error.
11. Verify the bundle in a clean offline environment.

Author representative scenarios through a versioned, data-only MissionPack.
Never commit operational details, CUI, personal data, credentials, or live
vulnerability information to this public repository.

## Phase 3 — assemble the review package

Complete `federal-profile.yaml`, export FederalProof, and route artifacts to the
system owner, AI governance lead, security assessor, privacy/civil-rights and
accessibility reviewers, acquisition team, legal counsel, and authorizing
official as applicable. Each discipline contributes evidence FederalProof does
not generate.

Where role-separated evidence review is useful, bind the completed
AssuranceGraph report to an organization-owned AssuranceQuorum policy. Require
the applicable security, evaluation, privacy, mission, and independent-review
functions, preserve `evidence-gap` statements, and keep the quorum result
separate from the authorizing official's decision. A satisfied quorum is not an
ATO, control determination, procurement approval, or risk acceptance.

Where reviewer-key lifecycle and log equivocation are material, place the
Quorum reviews in an organization-owned AssuranceLedger. Use separately
governed operator and witness keys, exchange checkpoint roots across independent
channels, preserve retirement and compromise declarations, and require new
review when trust is historical or invalidated. A witnessed checkpoint is
audit evidence—not identity proof, a control determination, or an ATO.
Use `ledger plan-rereview` to produce a technical claim/role worklist after a
reviewer-key event. Accountable officials still decide whether historical trust
is acceptable, who may perform replacement review, how an evidence gap is
resolved, and whether any operational response is required.

Before accepting a package, fork, or technology-partner upgrade, emit and
verify `ledger capabilities`, then place an owner-reviewed `ledger
lock-capabilities` artifact under the agency's normal configuration-control
process. Run `ledger check-capability-lock --fail-on-drift` in CI and retain its
JSON/SARIF evidence. The lock may establish an exact technical compatibility
floor; because it is unsigned, it does not establish who approved that floor and
does not replace configuration control, supply-chain review, or authorization.

Where multiple components or partners must share the policy and key authority,
establish an organization-owned AssuranceTrustRoot. Bootstrap its first exact
digest through the agency's approved independent distribution process, persist
the last trusted version, set a reviewed expiration, require separately
governed root signers, and authorize exact Ledger, ObserverReceipt, and Quorum
policy digests. Every rotation should be evaluated against the previously
trusted root so both old and new thresholds approve the same canonical payload.
`trusted_rotation` is technical continuity evidence; it is not identity
proofing, key-custody assurance, a FIPS determination, an ATO, or approval of
the policies it carries.

For intermittently connected enclaves, long-lived operational technology, and
vendor appliances that can miss several rotations, retain every numbered root
and run `ledger evaluate-trust-chain` before accepting the new policy authority.
Set `--minimum-final-version` from an independently governed release or
configuration-management channel. The chain verifier accepts an expired root
only as a historical intermediate, requires a current final root, and records
every old/new threshold result. It does not retrieve metadata, prove that the
presented chain is the latest, or authorize installation of the update.

Exercise threshold-loss and compromise response before deployment with a
root-authorized TrustRecoveryDrill policy. Assign incident commander, key
custodian, independent approver, distributor, and auditor roles; require the
custodian and approver to remain actor-separated; set agency-owned response
windows and an exercise-age limit; retain the real records locally; and export
only their fixed evidence classes and digests. Treat
`recovery_readiness_evidenced` as tabletop evidence, not permission to bypass
the old root threshold, issue emergency credentials, skip incident reporting,
or activate a replacement root.

Where an agency or inter-organizational exercise needs actor-authenticated
handoffs, add a separate TrustRecoveryAttestation policy with dedicated keys
for each assigned recovery role. Require all nine in-toto/DSSE event envelopes,
unique exercise nonces, and the complete preceding-envelope digest chain. Pin
the authorizing root through an independent configuration-management channel
and retain private keys in agency-approved custody. Treat
`authenticated_recovery_handoffs` as evidence that the policy-authorized keys
signed the exact simulated events—not proof of PIV identity, successful
recovery, compliance, ATO approval, or authority to change a trust anchor.

Where an assurance decision crosses organizations, isolated enclaves, or OT
systems and depends on time, use AssuranceTimeQuorum as supporting evidence for
the agency's SC-45 implementation—not as the implementation itself. Pin an
owner-reviewed source policy through configuration management, use separately
administered sources and a fresh retained nonce for each artifact, set maximum
source radius and final interval width, and preserve divergent results. Treat
`bounded_time_corroborated` as evidence that authorized keys signed overlapping
intervals for that request. It is not proof of UTC accuracy, source
independence, compliant time synchronization, a control assessment result, or
an ATO, and it never sets a system clock.

For a root-acceptance decision, pass that report to TrustRootTimeGate with the
agency-retained policy digest and nonce, the independently controlled root
anchor, trust domain, minimum version, and exact authorized policy inputs. The
gate requires the complete root decision to pass at both interval endpoints,
so an issuance or expiration boundary inside clock uncertainty remains a
visible failure. Treat `temporally_trusted_root` as portable decision evidence,
not a trust-anchor installation, FIPS determination, control assessment,
authorization to operate, or proof that no newer root was withheld.

For the remaining distribution question, use RootViewQuorum with observers
operated through meaningfully separate agency, integrator, laboratory, sector,
or enclave paths. Retain the observer-policy digest in configuration control
and generate a fresh nonce for each candidate-root decision. A matching
observer and declared-organization threshold can corroborate the supplied
distribution view; a lagging response remains visible, and one valid same-
version conflict or higher-version response blocks acceptance even when a
majority matches. Investigate those outcomes and retrieve the full continuity
chain through the agency's approved process. `root_view_corroborated` is not
proof of nationwide or ecosystem-wide dissemination, actual organizational
independence, a current global root, a control assessment, an ATO, or approval
to install the candidate.

Before accepting an implementation from an integrator or technology partner,
require it to execute the committed RootViewQuorum v1 known-answer pack and
retain the verifier output with the reviewed build. The eight cases give both
sides identical bytes and expected decisions for positive, fail-closed, and
tamper-rejection behavior without exposing a production root or key. This is a
repeatable integration check, not FIPS validation, NIST ACVP/CAVP, product
certification, a control assessment, or evidence that untested inputs are safe.

For pre-solicitation or vendor comparison, create a separate owner-approved
AcquisitionProof profile. Use the same frozen mission protocol for every
candidate, report missing cost or outcome observations as missing, and treat
the generated QASP, portability, pricing, and reevaluation artifacts as drafting
inputs—not source-selection decisions.

## Phase 4 — controlled pilot and monitoring

- deploy least privilege with server-side authorization;
- require approvals bound to the exact action and resource;
- support safe stop, rollback, incident response, and human remedy;
- measure field failures and near misses without collecting unnecessary data;
- reassess after model, prompt, policy, tool, data, or provider changes; and
- retire the capability when benefit no longer exceeds cost and risk.

ContinuousProof can content-address an approved report and flag later identity
or metric drift. Program owners define thresholds, review triggers, response,
and risk disposition; the command is not a production monitor.

## Design-partner contribution

Public agencies, state/local/tribal partners, critical-infrastructure operators,
small businesses, and researchers can propose an inert mission pack using the
**Federal mission pack** issue form. A useful contribution provides synthetic
records, authoritative facts, one isolated adversarial variable, functionally
observable outcomes, explicit affected stakeholders, and primary-source policy
context. Do not submit a real incident or controlled information.
