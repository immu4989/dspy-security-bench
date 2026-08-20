# FederalProof: standards-shaped evidence without certification theater

FederalProof converts a **verified** repeated ImpactTwin, ControlTwin,
IncidentTwin, MissionPack, or AuthorityTwin evidence bundle into a
content-addressed review pack. It combines
technical observations with an owner-supplied deployment profile and produces:

- OSCAL 1.2.2 Assessment Results JSON;
- OSCAL 1.2.2 POA&M JSON when a local objective fails;
- a draft AI impact-assessment evidence annex;
- a draft performance/QASP scorecard;
- the versioned informative control crosswalk; and
- a manifest that binds every file by SHA-256.

FederalProof does **not** decide compliance, high-impact status, award,
acceptance, risk acceptance, or authorization to operate. It is not affiliated
with or endorsed by the U.S. Government or NIST.

## Quick start

First create a repeated evidence bundle; the offline IncidentTwin fixture is a
safe way to learn the workflow:

```bash
dspy-security-bench incident repeat \
  --agent dspy_security_bench.incident.agents:build_bounded_reference \
  --trials 5 --json incident-repeat.json
dspy-security-bench incident submit-result incident-repeat.json \
  --submitter maintainer \
  --agent-source https://github.com/immu4989/dspy-security-bench \
  --out incident-evidence.json
```

Create and complete a deployment profile:

```bash
dspy-security-bench federal init --out federal-profile.yaml
# Replace every REPLACE value and .example URI.
dspy-security-bench federal profile-validate federal-profile.yaml
```

Export and verify:

```bash
dspy-security-bench federal export incident-evidence.json \
  --profile federal-profile.yaml \
  --out-dir artifacts/federalproof
dspy-security-bench federal verify artifacts/federalproof
```

An export returns status 1 when an objective fails but still preserves the
evidence and creates a POA&M input. Integrity failures return status 2.

## Profile responsibilities

The system owner supplies the mission, deployment context, authorization
boundary, data classification, high-impact determination and rationale,
Assessment Plan/SSP references, accountable owners, human oversight, fail-safe,
remedy, reassessment cadence, and local acceptance thresholds. Placeholder
`.example` references, missing fields, unknown fields, and unsafe URI schemes
are rejected.

Thresholds use lower confidence bounds for rates. This discourages accepting a
candidate merely because a small run happened to score 100%. Thresholds are
local risk decisions; the project does not provide universal federal cutoffs.

## OSCAL model

Assessment findings target FederalProof’s local objective identifiers—not NIST
SP 800-53 control identifiers. External mappings are recorded as informative
remarks because a benchmark observation cannot establish that a system control
is implemented or satisfied. The Assessment Results import the owner-supplied
Assessment Plan. A generated POA&M imports the owner-supplied SSP and leaves
remediation dates to accountable officials rather than inventing them.

The exporters are validated against the official [OSCAL 1.2.2 model
schemas](https://pages.nist.gov/OSCAL-Reference/models/v1.2.2/). Downstream
programs should validate their complete document set, UUID lifecycle, linked
AP/SSP content, profiles, extensions, and FedRAMP or agency-specific constraints.

## Policy basis and limits

The crosswalk references current primary material including OMB M-25-21,
M-25-22, M-26-04, the NIST AI RMF and GenAI Profile, NIST AI 100-2e2025,
SP 800-53, SP 800-218A, NIST's agentic evaluation-probes project, and GAO's
high-impact AI testing practices. It only identifies where an observation may
support human assessment.

In particular, IncidentTwin does not evaluate the truth-seeking or ideological
neutrality principles in OMB M-26-04. FederalProof only helps preserve an
evaluation methodology and result; agencies must design appropriate factuality,
neutrality, multilingual, accessibility, civil-rights, privacy, and end-user
feedback evaluations for the actual use case.

MissionPack/SourceTwin evidence adds local objectives for citation
faithfulness, completeness, sufficiency, and preference for current primary
sources. These test traceable grounding within the exact embedded synthetic
pack. They do not establish the truth of real agency source material, legal
interpretation, ideological neutrality, or the correctness of a production
decision. See [MissionForge and SourceTwin](missionforge.md).

AuthorityTwin evidence adds local objectives for delegated-authority attack
resistance, clean-request utility, injected decision accuracy, simulated-effect
containment, and normalized receipt integrity. Its informative crosswalk also
references NIST's AI Agent Standards Initiative and the NCCoE software/AI agent
identity and authorization concept paper. Those materials frame active needs;
they do not define an AuthorityTwin certification, and NIST does not endorse
this project. Passing the synthetic protocol does not prove production identity,
least privilege, non-repudiation, or control implementation. See
[AuthorityTwin](authority-twin.md).

## Vendor-neutral comparison

```bash
dspy-security-bench federal compare artifacts/vendor-a artifacts/vendor-b \
  --json-out artifacts/comparison.json
```

Comparison is defensible only when mission, protocol version, agent boundary,
policy, tools, trial counts, provider settings, and deployment conditions are
materially equivalent. Preserve unfavorable trials and document changes.
