# Federal and regulated-enterprise adoption path

This guide describes a practical pilot path. It is not legal, acquisition,
privacy, civil-rights, accessibility, cybersecurity, or authorization advice.

## Phase 0 — choose a bounded mission

Start with an advisory workflow whose outputs receive human review. Name the
affected people, intended benefit, disallowed outcomes, data boundary, tool
authority, appeal/remedy path, and an accountable system and risk owner. Do not
begin with autonomous irreversible action.

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

1. Run ImpactTwin for procurement decision and economic-integrity failures.
2. Run IncidentTwin for cyber-response side effects and approval boundaries.
3. Run ControlTwin/RepeatControlTwin to show that the proposed policy changes
   functional outcomes without destroying clean utility.
4. Retain every raw trial and runtime error.
5. Verify the bundle in a clean offline environment.

Then add agency-authored representative scenarios through a versioned pack.
Never commit operational details, CUI, personal data, credentials, or live
vulnerability information to this public repository.

## Phase 3 — assemble the review package

Complete `federal-profile.yaml`, export FederalProof, and route artifacts to the
system owner, AI governance lead, security assessor, privacy/civil-rights and
accessibility reviewers, acquisition team, legal counsel, and authorizing
official as applicable. Each discipline contributes evidence FederalProof does
not generate.

## Phase 4 — controlled pilot and monitoring

- deploy least privilege with server-side authorization;
- require approvals bound to the exact action and resource;
- support safe stop, rollback, incident response, and human remedy;
- measure field failures and near misses without collecting unnecessary data;
- reassess after model, prompt, policy, tool, data, or provider changes; and
- retire the capability when benefit no longer exceeds cost and risk.

## Design-partner contribution

Public agencies, state/local/tribal partners, critical-infrastructure operators,
small businesses, and researchers can propose an inert mission pack using the
**Federal mission pack** issue form. A useful contribution provides synthetic
records, authoritative facts, one isolated adversarial variable, functionally
observable outcomes, explicit affected stakeholders, and primary-source policy
context. Do not submit a real incident or controlled information.
