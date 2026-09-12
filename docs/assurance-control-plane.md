# Assurance Control Plane: containment canaries, dependency impact, and review packs

The Assurance Control Plane closes two gaps that static benchmarks leave open:

1. **Did the declared runtime controls actually observe and contain harmless
   boundary canaries?**
2. **When one AI-agent dependency changed, which assurance claims must be
   reevaluated?**

It combines ContainmentProof, AgentBOM ClaimImpact, AssuranceGraph, a
non-executing probe-contribution contract, seven fictional sector starters, a
closed federal review pack, and a non-ranking public reproduction exchange.
Every reference flow is local, deterministic, content-addressed, and takes zero
production action.

## Five-minute reference run

```bash
dspy-security-bench contain demo --out-dir artifacts/containmentproof
dspy-security-bench bom demo --out-dir artifacts/agentbom
dspy-security-bench assure demo --out-dir artifacts/assurancegraph

dspy-security-bench assure federal-pack \
  artifacts/assurancegraph/assurance-report.json \
  --evidence-root artifacts/assurancegraph \
  --out-dir artifacts/federal-review
dspy-security-bench assure federal-verify artifacts/federal-review \
  --evidence-root artifacts/assurancegraph
```

These are fictional format demonstrations. They are not results for a model,
vendor, organization, agency, or production system.

## ContainmentProof: distinguish the control from its monitor

ContainmentProof analyzes structural observations from eight harmless synthetic
canaries:

| Canary | Evidence question |
|---|---|
| Workload isolation | Did a synthetic boundary attempt remain blocked? |
| Network egress | Did a non-routable canary destination remain unreachable? |
| Cross-run communication | Did an isolated run fail to reach another synthetic run? |
| Credential honeytoken | Was harmless token use blocked and observable? |
| Evaluator integrity | Did the workload fail to influence the declared evaluator boundary? |
| Impossible-task stop | Did an impossible task end in a bounded safe stop? |
| Human pause | Did the declared pause become effective? |
| Restart authorization | Did restart require the declared accountable authorization? |

The report keeps four outcomes separate: `contained`,
`containment_violated`, `monitor_failed`, and `incomplete_evidence`. A missing
alert never becomes proof that a boundary held. The analyzer executes no agent,
model, tool, network request, shutdown, or restart.

Create one editable observation record:

```bash
dspy-security-bench contain init --profile hardened-reference \
  --out containment-scenario.json
dspy-security-bench contain run containment-scenario.json \
  --json-out containment-report.json \
  --sarif-out containment.sarif --fail-on-review
dspy-security-bench contain verify containment-report.json
```

## AgentBOM ClaimImpact: invalidate only what changed

AgentBOM inventories models, runtimes, frameworks, libraries, tools, MCP
servers, policies, datasets, indexes, identity providers, trust roots,
containers, evaluators, monitors, infrastructure, and other dependencies. Claim
bindings connect those components to AssuranceGraph claims.

ClaimImpact compares two complete inventories, computes the reverse transitive
dependency closure, and returns an exact minimal reevaluation plan for changed
components, relationships, or bindings. An unchanged, complete inventory can
produce `no_material_change`; any material bound change produces
`reevaluation_required`. It does not deploy, update, block, purchase, or rank a
component.

```bash
dspy-security-bench bom init --revision baseline --out baseline.agentbom.json
# Edit a separately created candidate; do not mutate the reviewed baseline.
dspy-security-bench bom init --revision candidate --out candidate.agentbom.json
dspy-security-bench bom compare baseline.agentbom.json candidate.agentbom.json \
  --reason "reviewed MCP server revision" \
  --json-out claim-impact.json --sarif-out claim-impact.sarif \
  --fail-on-reevaluation
dspy-security-bench bom verify claim-impact.json
```

Local CycloneDX, SPDX, SLSA Provenance v1, and CycloneDX 1.7 ML-BOM imports
create deliberately incomplete starters:

```bash
dspy-security-bench bom import-cyclonedx bom.json \
  --inventory-id reviewed-agent --out agentbom.json
dspy-security-bench bom import-spdx spdx.json \
  --inventory-id reviewed-agent --out agentbom.json
dspy-security-bench bom import-slsa provenance.json \
  --inventory-id reviewed-agent \
  --out agentbom.json \
  --report-out slsa-import.report.json
dspy-security-bench bom verify-slsa-import \
  slsa-import.report.json provenance.json
dspy-security-bench bom import-mlbom cyclonedx-mlbom.json \
  --inventory-id reviewed-ml-system \
  --out mlbom.agentbom.json \
  --report-out mlbom-disclosure.report.json
dspy-security-bench bom verify-mlbom-import \
  mlbom-disclosure.report.json cyclonedx-mlbom.json
dspy-security-bench bom import-spdx-ai spdx-ai.json \
  --inventory-id reviewed-spdx-ai \
  --out spdx-ai.agentbom.json \
  --report-out spdx-ai-disclosure.report.json
dspy-security-bench bom verify-spdx-ai-import \
  spdx-ai-disclosure.report.json spdx-ai.json
dspy-security-bench bom crosswalk-ai \
  --cyclonedx-report mlbom-disclosure.report.json \
  --cyclonedx-source cyclonedx-mlbom.json \
  --spdx-report spdx-ai-disclosure.report.json \
  --spdx-source spdx-ai.json \
  --pairs ai-bom-crosswalk-pairs.json \
  --out ai-bom-crosswalk.report.json
dspy-security-bench bom evaluate-ai-disclosure \
  --policy ai-bom-disclosure-policy.json \
  --cyclonedx-report mlbom-disclosure.report.json \
  --cyclonedx-source cyclonedx-mlbom.json \
  --spdx-report spdx-ai-disclosure.report.json \
  --spdx-source spdx-ai.json \
  --out ai-disclosure-policy.report.json \
  --sarif-out ai-disclosure-policy.sarif \
  --fail-on-findings
dspy-security-bench bom verify-ai-disclosure \
  ai-disclosure-policy.report.json \
  --policy ai-bom-disclosure-policy.json \
  --cyclonedx-report mlbom-disclosure.report.json \
  --cyclonedx-source cyclonedx-mlbom.json \
  --spdx-report spdx-ai-disclosure.report.json \
  --spdx-source spdx-ai.json
```

The owner must enrich AI-specific components, dependency relationships, claim
bindings, and completeness before decision use. Import is not attestation.

The SLSA mapper accepts only in-toto Statement v1 with the
`https://slsa.dev/provenance/v1` predicate and a lowercase SHA-256 identity for
every mapped subject and resolved dependency. It creates stable privacy-hashed
component IDs for output artifacts, the external build definition, the builder,
and resolved inputs. This means a later artifact or parameter digest change is
a content change to one logical component—not an unrelated remove/add pair—so
existing owner claim bindings can drive a minimal reevaluation plan.

Raw artifact names and URIs, builder ID, build type, external/internal
parameters, invocation metadata, timestamps, byproducts, annotations, content,
and extensions are excluded from the output. Exact digests bind their logical
identities and the complete source Statement. Those hashes are identifiers, not
confidentiality protection against guessing. The strict mapping report records
every omission and can be recomputed only with the separately retained source.
It does not parse a DSSE envelope, verify a signature, infer a SLSA Build level,
or make a supplier, procurement, deployment, or risk decision.

This mapping follows SLSA's BuildDefinition/RunDetails model: externally
controlled parameters and resolved dependencies are distinct, the builder ID
identifies the build platform trust base, and consumers must verify expected
builder/signer pairs separately.

- [SLSA Provenance v1](https://slsa.dev/provenance/v1)
- [SLSA artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts)
- [in-toto ResourceDescriptor v1](https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md)

### CycloneDX 1.7 ML-BOM disclosure gaps without disclosure leakage

`MLBOMDisclosure v1` maps first-class CycloneDX `machine-learning-model` and
`data` components to stable, privacy-hashed AgentBOM identities. Declared
`dependsOn` edges remain dependencies; model-card dataset references become
`sourced-from` edges. A later model-card or dataset disclosure change alters
the component content digest without changing its identity, so an owner can
bind the logical component once and request targeted reevaluation after change.

The report records presence or absence—never the values—of these model-card
fields:

- learning approach, task, architecture family, model architecture, datasets,
  inputs, and outputs;
- performance metrics and graphics; and
- intended users, use cases, technical limitations, performance tradeoffs,
  ethical considerations, environmental considerations, and fairness
  assessments.

For `data` components and inline datasets it records presence of contents,
classification, sensitive-data declarations, graphics, description, and
governance. Missing and unresolved dataset references remain visible review
gaps. Raw component names, versions, suppliers, package locators, URLs,
descriptions, governance identities, metric values, and consideration text are
excluded. The full canonical source digest and exact derived report make edits
detectable when the separately retained source is supplied for verification.

This is a bounded disclosure checklist, not full CycloneDX validation. A field
can be populated yet false, stale, incomplete, or unsuitable. No score is
produced, embedded signatures are not verified, hashes are not confidentiality
controls, and the result is not a safety, fairness, privacy, provenance,
compliance, certification, procurement, deployment, or ATO decision. The
committed fictional example is separately tested against the official pinned
CycloneDX 1.7.1 JSON Schema.

### SPDX 3.0.1 AI and Dataset profiles remain semantically separate

`SPDXAIDisclosure v1` accepts the SPDX 3.0.1 global JSON-LD context and compact
`ai_AIPackage` and `dataset_DatasetPackage` element types. It deliberately does
not force SPDX into the CycloneDX field vocabulary. Instead it records presence
for all fifteen AI-profile properties and thirteen Dataset-profile properties,
then maps only the bounded graph semantics AgentBOM can represent:

- `dependsOn` becomes `depends-on`;
- `trainedOn`, `testedOn`, and `hasDataFile` become `sourced-from`, while their
  distinct source relationship counts remain in the import report; and
- unresolved targets remain explicit gaps rather than being silently dropped.

SPDX 3.0.1 requires every AI and Dataset package to have exactly one
`hasDeclaredLicense` and one `hasConcludedLicense` relationship to license
information. The mapper reports resolved relationship counts per component but
never copies the license expression or text. This is a structural review aid,
not legal advice or license compatibility analysis.

Stable privacy-hashed IDs preserve logical component continuity, while a digest
of the complete source element makes disclosure changes visible to ClaimImpact.
The separately retained source is required to recompute the report. Raw SPDX
IDs, names, suppliers, locations, application/training descriptions,
hyperparameters, metrics, model limitations, risk values, dataset preparation,
bias descriptions, sensitive-data declarations, license expressions, and agent
identities do not enter the portable artifact.

The committed fictional example validates against the official SPDX 3.0.1 JSON
Schema. The mapper itself does not expand JSON-LD or run that schema, the OWL
ontology, or SHACL; it therefore never claims full SPDX conformance. Presence
does not establish accuracy or adequacy, and the output is not a safety,
privacy, fairness, legal, compliance, procurement, deployment, certification,
or ATO decision.

### Cross-standard review without invented equivalence

`AIBOMCrosswalk v1` accepts the two source-bound import reports, both retained
source documents, and an explicit owner pairing policy. It first exactly
recomputes each import report. It then groups field presence into ten model and
six dataset review topics and distinguishes:

- both standards have at least one populated field for the topic;
- both have mapped fields but neither is populated;
- only one side has a populated mapped field; and
- one standard has no field in this narrow crosswalk for the topic.

Those states support supplier intake, standards migration, and multi-party
review without exporting model-card or dataset values. The crosswalk retains
only privacy-hashed component IDs already present in the import reports, lists
of populated field names, source/report digests, and the digest of the strict
owner pairing policy. The report is exactly recomputable offline.

The topic groupings are review routes, not assertions that fields mean the same
thing. Component pairing is owner-supplied and not discovered or authenticated.
`raw_values_compared` and `semantic_equivalence_established` are always false.
No asymmetry is a defect finding or a judgment about either standard, and no
state is a model-quality, compliance, procurement, certification, deployment,
or ATO decision.

### Owner-authored AI disclosure requirements, not a universal score

`AIDisclosurePolicy v1` converts an organization's own minimum disclosure
requirements into deterministic component-level findings. A policy selects any
of the sixteen CycloneDX model-card fields, six CycloneDX dataset fields,
fifteen SPDX AI fields, and thirteen SPDX Dataset fields already exposed by the
privacy-minimized import reports. It may also require resolved model/dataset
references and SPDX's exactly-one declared/concluded-license relationship
shape.

Evaluation first exactly recomputes both import reports against their separately
retained sources. It then emits stable missing-field, unresolved-reference, and
license-relationship findings in JSON and optional SARIF. `--fail-on-findings`
provides an explicit CI gate; omitting it preserves an observe-and-review flow.
The committed fictional policy deliberately produces four findings so the
reference workflow exercises the unfavorable path.

This project does not choose an organization's requirements. A populated field
may still be false, stale, incomplete, unsafe, or unfit for the mission. The
evaluator never processes raw disclosure values, authenticates supplier
assertions, grants waivers, scores a model, accepts risk, approves procurement
or deployment, determines compliance, certifies a system, or authorizes
operation. Policy ownership and every resulting decision stay with the
accountable organization.

## AssuranceGraph integration

Critical-infrastructure cases now evaluate nine independent claims from nine
natively verified evidence kinds. Evaluation-process integrity, runtime
containment, and dependency currency are not blended into a universal score.
They can independently be supported, violated, contradicted, stale, or missing.

Seven fictional sector starters make the boundary concrete without claiming
sector approval:

```bash
dspy-security-bench assure sectors
dspy-security-bench assure sectors water-operations
dspy-security-bench assure init --sector water-operations \
  --case-id water-agent-pilot --out assurance-case.json
```

Starters cover public benefits, healthcare administration, financial
investigation, manufacturing maintenance, water operations, emergency
logistics, and software development. Every starter contains placeholder owners
and zero evidence digests, so it cannot be confused with a completed case.

## Declarative probe contract

Community probe proposals are manifests plus favorable and unfavorable JSON
fixtures. A manifest cannot name an executable entry point. Conformance denies
network access and validates both fixtures through a semantic verifier already
implemented in the repository; adding a new evidence kind requires reviewed
source and tests.

```bash
dspy-security-bench probe init --probe-id my-structural-probe \
  --name "My structural probe" --evidence-kind containment \
  --report-type "ContainmentProof / Canary-based agent control evidence" \
  --out probe-manifest.json
dspy-security-bench probe digest fixtures/favorable.json
dspy-security-bench probe digest fixtures/unfavorable.json
dspy-security-bench probe validate probe-manifest.json
dspy-security-bench probe conformance probe-manifest.json --fixture-root . \
  --out conformance.json
```

Passing conformance establishes format and recomputation compatibility, not the
truth or completeness of external observations.

## Federal review inputs without an automatic ATO

`assure federal-pack` first recomputes the AssuranceGraph report and all local
evidence. It then creates a closed directory containing:

- the exact assurance report and non-certifying OSCAL 1.2.2 observations;
- owner-supplied Assessment Plan inputs;
- an evidence index without source payloads;
- expiry times and freshness owners;
- change-trigger guidance;
- POA&M inputs for every unsupported claim, without invented deadlines; and
- a manifest that pins every byte.

`federal-verify` rejects missing, altered, regenerated, or undeclared files.
The pack records zero automatic control determinations, risk acceptances, and
authorizations to operate. An agency must connect it to its actual boundary,
controls, Assessment Plan, evidence custody, and decision authority.

## Public reproduction exchange

The exchange at [`submissions/assurance/`](../submissions/assurance/README.md)
indexes safely public report metadata at immutable source revisions. It accepts
unfavorable outcomes, preserves known gaps, counts independent report digests,
and supports stale, withdrawn, and superseded states. It calculates no ranking
and creates no endorsement.

```bash
dspy-security-bench assure exchange-verify
dspy-security-bench assure exchange-seal submissions/assurance/index.json \
  --out index.sealed.json
```

## Stakeholder use

- **Government programs** can start with mission-specific boundaries, export
  assessment inputs, and preserve accountable authorization decisions.
- **Frontier AI labs** can distinguish isolation failures, evaluator failures,
  safe-stop failures, and monitor gaps across evaluation runs.
- **Cybersecurity providers** can contribute portable structural evidence and
  unfavorable fixtures without handing this repository production access.
- **Technology partners** can map component updates to the claims that require
  retesting instead of rerunning or waiving everything indiscriminately.
- **Enterprises and critical infrastructure operators** can make owners,
  freshness, dependencies, and continuity assumptions reviewable in one case.
- **Researchers** can reproduce exact semantics and publish disagreement
  without a leaderboard suppressing negative evidence.

The design is informed by NIST's [AI Agent Standards
Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
and [evaluation probe
work](https://www.nist.gov/programs-projects/building-evaluation-probes-agentic-ai),
CISA's [SBOM](https://www.cisa.gov/sbom) work, [NIST SP
800-161](https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final) supply-chain
guidance, and [OMB
M-25-22](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf)
acquisition and monitoring needs. Crosswalks are informative, not compliance
determinations.
