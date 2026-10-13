# ProofRun: verifiable evidence for AI-agent security evaluations

Most agent benchmarks end at a score in a log. ProofRun turns a RepeatTwin,
RepeatControlTwin, RepeatIncidentTwin, repeated MissionPack, or
RepeatAuthorityTwin run into a portable evidence passport: raw trial outcomes,
uncertainty, protocol and policy identity, source commit, workflow identity,
and a cryptographic attestation over the exact JSON bytes.

ProofRun is designed for teams that need to answer two separate questions:

1. **Is this result internally reproducible?** Offline verification recomputes
   every rate, Wilson interval, outcome class, usage total, protocol hash, and
   content digest from the preserved trials.
2. **Where did these bytes come from?** GitHub artifact attestations bind the
   bundle to a repository, commit, ref, workflow run, and hosted-runner identity.

Those properties make evidence easier to exchange between an AI vendor, a
customer, an auditor, and a public-sector procurement team without pretending
that workflow provenance is a safety or compliance certificate.

## Who this serves

- **Public agencies and acquisition teams** get a machine-readable, synthetic
  test artifact whose protocol, source commit, uncertainty, and chain of custody
  can be inspected without receiving vendor credentials or restricted data.
- **AI vendors and startups** get one portable workflow for producing evidence
  customers can independently recompute, reducing bespoke security
  questionnaires and repeated integration work.
- **Enterprise security teams** get a regression gate that preserves failed
  evidence for incident analysis instead of discarding the most useful run.
- **Researchers and users** get raw trials, honest limitations, and a forkable
  path to challenge, reproduce, or extend a published result.

This supports better technical due diligence and faster adoption; it does not
replace an agency's acquisition process, an organization's risk assessment, or
provider-side audit evidence. It directly supports NIST's stated direction for
[reproducible agent-evaluation probes and machine-readable audit trails](https://www.nist.gov/programs-projects/building-evaluation-probes-agentic-ai).

## Fastest path: the trusted reusable workflow

Add this workflow to the repository containing the agent:

```yaml
name: Agent security evidence

on:
  workflow_dispatch:
  pull_request:

permissions:
  contents: read
  id-token: write
  attestations: write

jobs:
  proofrun:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.19.0
    with:
      agent: myapp.security:build_agent
      trials: 10
      min-lower-bound: 0.80
      submitter: "@your-handle"
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

The callable must take no arguments and return a fresh framework-neutral
`Agent`. The workflow checks out the evaluated commit, installs it in an
isolated Python environment, installs the immutable v0.19.0 ProofRun engine last,
runs the five clean/poisoned procurement pairs repeatedly, and preserves the
bundle even when the statistical gate fails. It then creates GitHub/Sigstore
build provenance and uploads the exact file as a workflow artifact.

Pin the reusable workflow to a release tag or full commit SHA. Do not use
`@main` for evidence you expect another organization to rely on.

### Control-effectiveness mode

Use the same trusted builder to evaluate an exact enforcement policy rather
than the agent alone:

```yaml
jobs:
  control-evidence:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.19.0
    with:
      evidence-kind: control
      agent: myapp.security:build_agent
      policy: policies/production.yaml
      approval-handler: myapp.approvals:review_tool_call
      trials: 10
      min-containment-lower-bound: 0.70
      min-clean-preservation-lower-bound: 0.80
      max-unstable-pairs: 1
```

The builder runs paired policy-off/policy-on trials, binds the normalized policy
and digest, keeps containment, mission recovery, and clean utility separate,
and generates an SVG evidence card beside the attested JSON. `policy` must be a
repository-relative path. Its public source defaults to the caller's exact
commit, or can be set explicitly with `policy-source`.

See the [Open Control Evidence Registry](control-evidence-registry.md) for the
admission and public-submission contract.

### Incident-response mission-assurance mode

Use `evidence-kind: incident` to test whether hostile alert content can redirect
an AI responder into five concrete operational harms while authoritative facts
remain fixed:

```yaml
jobs:
  incident-evidence:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.19.0
    with:
      evidence-kind: incident
      agent: myapp.security:build_incident_agent
      trials: 10
      min-lower-bound: 0.80
      submitter: "@your-handle"
```

The builder preserves functional state transitions and causal trace differences,
not just model text. See the [IncidentTwin protocol](incident-twin.md).

### MissionPack and SourceTwin mode

Use `evidence-kind: source` for the packaged SourceTwin protocol or a custom,
repository-relative data-only MissionPack:

```yaml
jobs:
  source-evidence:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.19.0
    with:
      evidence-kind: source
      mission-pack: evaluations/benefits-grounding.yaml
      agent: myapp.security:build_source_agent
      trials: 10
      min-lower-bound: 0.80
      submitter: "@your-handle"
```

The pack path cannot be absolute or contain `..`. The trusted builder loads it
from the evaluated commit, embeds it in every trial, binds its canonical digest,
and recomputes structured claims, citation chains, pair outcomes, uncertainty,
and content hashes in the credential-free verification job. Use the built-in
alias `source-twin` to avoid a custom file. See [MissionForge and
SourceTwin](missionforge.md).

### Delegated-authorization mode

Use `evidence-kind: authority` when the callable returns a fresh
`AuthorityAdapter` instead of an agent. The same trusted builder applies the
frozen 10-pair authorization protocol, recomputes normalized decision receipts
in a credential-free job, and preserves the bundle before gating:

```yaml
jobs:
  authority-evidence:
    uses: immu4989/dspy-security-bench/.github/workflows/proofrun.yml@v0.19.0
    with:
      evidence-kind: authority
      agent: myapp.authority:build_adapter
      trials: 10
      min-lower-bound: 0.70
      submitter: "@your-handle"
```

The `agent` input is retained for composite-action compatibility; in authority
mode it names the adapter factory. See [AuthorityTwin](authority-twin.md) for
the adapter contract, threat model, registry, and interpretation limits.

## Flexible path: the composite action

The composite action creates missing parent directories for its `output` and
control-only `card-output` inputs. Use new, literal workspace-relative filenames
(for example `artifacts/run-001/evidence.json`); existing files, symlinks, parent
traversal, glob patterns, and colliding bundle/card paths are rejected before
evaluation. The standalone CLI still requires pre-existing parent directories.

Only an experiment completing with exit 0 (gate passed) or 1 (gate failed) enables
artifact inspection, upload, and optional attestation. Exit 2 preflight/runtime
errors do not authorize publishing a retained file from an earlier invocation.
Failed statistical gates still preserve their new evidence before the action
fails. Non-control runs never upload a leftover control card. These checks are
not a sandbox against evaluated code running in the same job; use the isolated
reusable workflow for the stronger execution/attestation separation.

Use the action when an existing job needs custom setup before evaluation:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
  - uses: immu4989/dspy-security-bench@v0.19.0
    with:
      agent: myapp.security:build_agent
      trials: "10"
      min-lower-bound: "0.80"
```

This path is cryptographically tied to the caller's workflow. It earns the
`github_attested` evidence tier, while the centrally controlled reusable
workflow can earn `trusted_builder`.

## Local run and verification

```bash
dspy-security-bench proofrun run \
  --agent myapp.security:build_agent \
  --trials 10 \
  --min-lower-bound 0.80 \
  --submitter "@your-handle" \
  --agent-source "https://github.com/you/your-agent" \
  --out proofrun.json

# Recompute all evidence without network access.
dspy-security-bench proofrun verify proofrun.json --offline

# Verify the exact bytes and GitHub/Sigstore provenance.
gh auth login
dspy-security-bench proofrun verify proofrun.json

# Require the centrally controlled reusable-workflow identity.
dspy-security-bench proofrun verify proofrun.json --require-trusted-builder
```

Online verification rejects self-hosted-runner attestations by default. A
reviewer can opt in with `--allow-self-hosted-runner`, but should separately
evaluate that runner's trust and isolation.

### Verify one exact input snapshot

All nine registered bundle families use bounded strict JSON intake: at most 50,000,000
bytes, a UTF-8 object root, no duplicate members, no nonfinite numbers or
unpaired Unicode surrogates, and bounded nesting/numeric tokens. Unsupported
bundle types and malformed native evidence fail closed. Public diagnostics
withhold source-derived exception text and external process output.

Verification prints `Input snapshot sha256`, the SHA-256 of the exact file bytes
read once. To compare a handoff against a digest obtained through an independent
trusted channel, use:

```bash
dspy-security-bench proofrun verify proofrun.json --offline \
  --expected-file-sha256 "$EXPECTED_FILE_SHA256"
```

The pin is **not** the JSON `bundle_sha256` field: whitespace changes the file
digest but not the canonical bundle digest. A digest copied from the same
untrusted handoff supplies no independent authentication.

Online verification passes a private temporary copy of those original bytes to
`gh attestation verify`, then removes it, including on process failures. It does
not reopen the input path after native verification. The verdict describes that
snapshot, not whatever a concurrent writer might later put at the original
path. This prevents path-replacement drift between checks; it is not isolation
from malicious software running as the same OS user.

GitHub CLI remains responsible for cryptographic signature and artifact-digest
verification. ProofRun additionally requires a matching certificate's repository,
commit, ref, runner, and workflow-run claims. It accepts a matching verified
attestation even if earlier returned attestations do not match. Statement text
alone never supplies these identity checks; see the
[GitHub CLI verification contract](https://cli.github.com/manual/gh_attestation_verify).
Tests use simulated GitHub responses, not live signing or a live trust service.

Online collection is bounded independently of JSON parsing. The verifier retains
at most 5,000,001 stdout bytes (the final byte detects overflow), plus transport
chunks and a bounded returned copy; stderr is discarded, not retained or spooled
to disk. Stdin is closed so an unattended review cannot answer an interactive
prompt. Strict UTF-8 decoding does not depend on the machine's text encoding.
The strict JSON response limit remains 5,000,000 bytes including its internal
object wrapper. Oversized, malformed, unsuccessful, or incomplete output never
upgrades provenance, even if a valid-looking certificate appears in a prefix.

A 60-second collection deadline closes pipes and kills/reaps the direct verifier
child on timeout; overflow and caller interruption use the same cleanup. A
descendant retaining stdout cannot extend pipe collection beyond that deadline.
OS process creation and reaping may take longer; this is not a hard real-time
guarantee. Child/descendant CPU, memory, network access, credentials, and process
trees are not sandboxed. Use an organization-approved GitHub CLI installation
and runner containment. Authenticate through your normal GitHub CLI workflow
before verification; these checks never acquire or repurpose credentials.

Review exit codes are now consistent: `0` means native-valid and eligible (plus
verified provenance for online mode); `1` means valid but ineligible, or online
attestation was not verified; `2` means invalid evidence, malformed input/policy,
pin mismatch, or native verification failure. Earlier versions returned `1` for
some invalid native bundles. Offline success does not authenticate provenance.

### Machine-readable review decisions (on main)

Use the source checkout for this unreleased interface. `--json` emits exactly one
JSON object on stdout for a successfully parsed CLI request, including invalid
input and negative-verdict cases. Exit status is unchanged. Argument-parser errors
(such as a missing bundle argument) still use normal CLI stderr output.

```bash
dspy-security-bench proofrun verify supplier-bundle.json --offline --json \
  --minimum-trials 5 --expected-file-sha256 "$EXPECTED_FILE_SHA256"
```

For a service or intake pipeline, call the same implementation without parsing
terminal prose:

```python
from pathlib import Path
from dspy_security_bench.proofrun_review import ReviewPolicy, review_bundle

decision = review_bundle(
    Path("supplier-bundle.json"),
    policy=ReviewPolicy(minimum_trials=5, offline=True),
)
if decision["exit_code"] != 0:
    print("Review required:", decision["reason_code"])
else:
    print("Offline checks passed; provenance was not authenticated.")
```

The [packaged JSON Schema](../dspy_security_bench/schemas/proofrun-review.schema.json)
defines schema-v1 output, including required nullable fields and allowed verdict
combinations. Consumers should check `schema_version` and `exit_code`, not only
the presence of a bundle digest. Keep nonzero exit codes when piping CLI output
(for example, enable your shell's `pipefail` behavior).

| Outcome | Integrity | Eligibility | Provenance | Exit |
| --- | --- | --- | --- | --- |
| Offline checks pass | valid | eligible | not_checked | 0 |
| Online checks pass | valid | eligible | verified | 0 |
| Valid but insufficient for registry | valid | ineligible | not_checked | 1 |
| Signature/identity requirements not established | valid | eligible | unverified | 1 |
| Invalid policy, input, pin, or evidence | invalid or not_checked | not_checked | not_checked | 2 |

An online lookup is attempted only after native validity and eligibility pass.
Unverified provenance includes failed checks and unavailable external services;
it is not a claim that a signature is necessarily fraudulent. An offline review
cannot be combined with `--require-trusted-builder`: that contradictory policy
now exits 2, because offline replay cannot authenticate the builder.

### Structural evidence review (on main)

The same command and JSON decision interface also supports TraceProof, CausalProof,
CollectiveGuard v2, and DefenderTwin **submission bundles**. Select `--structural`
explicitly; these four protocols do not contain repeated-trial evidence:

```bash
dspy-security-bench proofrun verify structural-bundle.json --structural --offline --json \
  --expected-file-sha256 "$EXPECTED_FILE_SHA256"
```

For the Python API, use `ReviewPolicy(minimum_trials=None, offline=True)`.
`policy.minimum_trials: null` means structural review, not a disabled trial gate.
Omitting `--structural` retains the five-trial default for the five repeated
families. Applying a repeated-trial policy to a structural bundle, or a structural
policy to a repeated bundle, exits 2 with `policy_not_applicable` before native
replay. The CLI rejects combining `--structural` with `--minimum-trials`.

Each family still runs its full native verifier, including embedded-report
recomputation, privacy/disclosure rules, and eligibility checks. Native warnings
such as partial collection, missing instrumentation, private disclosure, or
known reference telemetry remain valid-but-ineligible (exit 1), not malformed
evidence. A valid, eligible bundle can contain adverse findings: review success
does **not** mean the system is secure or suitable for deployment. Inspect the
native report and apply your organization's decision policy separately.

Structural bundles remain self-attested. Without `--offline`, valid eligible
structural evidence returns `attestation_unverified` (exit 1) without invoking
GitHub: these contracts do not bind authenticated execution provenance. An
arbitrary signature over the JSON cannot upgrade that evidence. This distinction
follows the principle of checking artifact identity and expected provenance
separately in [SLSA's verification guidance](https://slsa.dev/spec/v1.2/verifying-artifacts);
this feature does not assign a SLSA level or establish compliance.

The unreleased schema-v1 review contract now admits the four additional bundle
types, nullable trial policy, and the mismatch reason. Existing repeated-family
output retains its field layout and semantics. Consumers using an earlier copy
of this unreleased schema must update it before accepting structural decisions;
the schema rejects structural authentication claims and policy-family mismatches.

### Review collection plan changes (on main)

Before replacing an approved collection plan, compare the proposed requirements
against baseline bytes whose SHA-256 you retained through an independent trusted
channel. This is useful for supplier renewals, internal policy updates, and
change-control reviews where an omitted evidence slot or relaxed provenance
requirement must not silently disappear.

```bash
dspy-security-bench proofrun compare-plans approved-plan.json proposed-plan.json \
  --expected-baseline-file-sha256 "$OWNER_RETAINED_PLAN_SHA256" --json
```

The baseline pin is mandatory. A mismatched or invalid baseline stops before the
candidate is read. Both plans use the existing strict plan validation: at most
25 entries and 1 MB each. No referenced artifacts are opened, no native replay or
GitHub lookup occurs, and neither plan is rewritten. The Python API is
`proofrun_plan_diff.compare_plans(baseline, candidate, expected_baseline_file_sha256=...)`.

Exit 0 means identical valid plan **bytes**, not verified evidence. Exit 1 means
changed bytes require owner review: `format_only` distinguishes formatting or
object-key-order changes from `requirements_changed`. Exit 2 means invalid
policy/input, a baseline-pin mismatch, or an invalid candidate; no partial diff
is emitted. Every change—including stricter policies—requires review. The tool
does not infer a universal security ranking or approve candidate requirements.

The [comparison schema](../dspy_security_bench/schemas/proofrun-plan-comparison.schema.json)
records the exact hashes and up to 50 union entries. Rows follow baseline order,
then candidate-only entries. Each row shows before/after positions and policies;
field changes include path, family, artifact hash, and all five policy inputs.
Reordering matters because collection resource budgets apply in plan order.
An ID rename is a removal plus an addition, not an inferred match. Labels, paths,
and repository names are fingerprinted rather than copied; hashes are linkable,
not anonymization. Text mode identifies entries by their 1-based positions.

After accountable owner review, retain the approved candidate's exact-byte hash
through your trusted channel and run `verify-collection` with that pin against
the actual artifacts. Reformatting also needs a new pin. A supplied plan/hash
pair or saved comparison report does not authenticate itself. This workflow
does not establish requirement completeness, independent execution, regulatory
compliance, or deployment approval.

### Practice a complete collection handoff (on main)

For a first owner/supplier/reviewer exercise, install a reviewed source revision
supporting the unreleased collection commands, then run:

```bash
dspy-security-bench proofrun collection-demo --out collection-walkthrough
```

No model credentials, external models, network calls, or operational data are
used. The destination must be new under an existing unlinked parent. Open
`collection-walkthrough/README.md` for six replay commands and their expected
exit codes. Open `reports/review.html`, `provenance-reports/review.html`, and
`missing-reports/review.html` beneath that directory to compare the three cases:

| Exercise | Native exit | Lesson |
| --- | --- | --- |
| Complete offline evidence | 0 | Every selected structural requirement is reviewed; provenance remains unauthenticated |
| Requested authenticated provenance | 1 | Structural evidence cannot establish authenticated execution merely because online mode was selected |
| Required defense evidence omitted | 2 | The missing requirement stays visible and cannot be outvoted by the other two artifacts |

The walkthrough uses bundled CollectiveGuard, CausalProof, and DefenderTwin
fixtures. It actually runs plan preparation, exact-byte snapshot creation,
pinned policy comparison, and native recipient reviews with synchronized
JSON/HTML/JUnit report sets. It validates the observed exit codes rather than
writing precomputed success reports. `demo.json` records the observed teaching
outcomes; it is a tutorial summary, not a new evidence or approval protocol.
The generator exits 0 only when all intended cases—including the failures—were
produced successfully. `--json` emits that summary to stdout. An unexpected
native result, existing destination, or output failure exits 2; partial new
files may remain for inspection, and retries require a fresh directory.

The generated README demonstrates preparing a draft, copying a pinned handoff,
generating a recipient report set, reviewing a policy change, and replaying both
adverse cases. Pins printed there identify the local fixture only, not independent
trust. Real recipients must retain owner-approved pins through a trusted channel.
The initial `recipient/` snapshot can be reviewed without the original `owner/`
directory. A fixed date marks synthetic fixture metadata, not observed execution.
Original fixture bytes and plans are deterministic; JUnit scope hashes can differ
across local paths, and verifier-version changes can change reports.

Do not submit these generated files as measured or independently reproduced
community results. Valid structural evidence can contain adverse findings, and
this fictional walkthrough does not establish that a deployment is safe, a
supplier is qualified, or a government's requirements are complete. Review
original artifact content before sharing real snapshots; the command does not
upload, sign, redact the originals, authorize disclosure, or change production.

### Required evidence collections (on main)

Use `proofrun verify-collection` when a supplier handoff or internal change review
requires several artifacts. Unlike a directory scan, an owner-controlled plan
defines the required set: a missing file is a failure, not an absent row. Every
entry binds an expected bundle type, exact input-file SHA-256, and explicit review
policy. All nine registry families are supported; each retains its native meaning.

#### Prepare a draft collection plan (on main)

Put the selected artifacts in `intake/`, then author `intake/requirements.json`.
Requirements have the plan's explicit slots and policies, but no file hashes.
For example, an owner choosing two offline structural requirements can write:

```json
{
  "schema_version": 1,
  "requirements_type": "ProofRun collection requirements",
  "entries": [
    {
      "id": "collective", "path": "collective.json",
      "bundle_type": "dspy-security-bench-collective-submission",
      "policy": {
        "minimum_trials": null, "offline": true,
        "attestation_repository": null, "require_trusted_builder": false,
        "allow_self_hosted_runner": false
      }
    },
    {
      "id": "defense", "path": "defense.json",
      "bundle_type": "dspy-security-bench-defense-evidence",
      "policy": {
        "minimum_trials": null, "offline": true,
        "attestation_repository": null, "require_trusted_builder": false,
        "allow_self_hosted_runner": false
      }
    }
  ]
}
```

```bash
dspy-security-bench proofrun prepare-plan intake/requirements.json \
  --out intake/plan.json --json
```

The output is a **draft**, never an approved requirement set. Preparation checks
strict JSON, declared family, and byte limits, then adds the SHA-256 of each
observed artifact without changing owner-selected policies. It does not run
agents, perform native evidence replay, contact GitHub, discover files, omit
missing entries, or infer requirements from supplied evidence. Invalid native
evidence can be pinned successfully and must still fail subsequent verification.

All requirements and the final encoded-plan size are admitted before artifact
reads. Limits are 1 MB of requirements, 25 slots, 50 MB per artifact, and 100 MB
aggregate artifact bytes, with one overflow-probe byte per attempted read.
Duplicate artifact hashes, missing/special/linked files, wrong declared families,
and invalid JSON fail the whole preparation; no partial plan is emitted on
input failure. Existing files are never overwritten. The output must be a new
portable `.json` filename beside the requirements so relative artifact paths
retain their meaning. No directories are created. A write failure can leave a
partial **new** output; inspect it before removing or retrying it.

For requirements retained through an independent trusted channel, additionally
pass `--expected-requirements-file-sha256 "$OWNER_REQUIREMENTS_SHA256"`. A pin
mismatch stops before artifact intake. Omitting it is allowed for initial draft
preparation and does not authenticate requirements. Never treat a supplier's
requirements/hash pair as your organization's approved scope.

`--json` emits only the [source-redacted receipt](../dspy_security_bench/schemas/proofrun-plan-preparation.schema.json),
including the exact draft-file hash and observed counts. The draft file itself
retains owner-selected IDs, paths, and repository names: review it before sharing.
The [requirements schema](../dspy_security_bench/schemas/proofrun-collection-requirements.schema.json)
reuses plan constraints; native validation additionally enforces distinct IDs,
paths, policies, and resource limits. Python callers can use
`proofrun_prepare.prepare_plan(path, expected_requirements_file_sha256=...)` to
receive `(full_content_plan_or_none, receipt)` without writing, or
`prepare_plan_file(path, output, ...)` to exclusively create the draft.

Use stable owner-controlled local directories. Observed hashes describe the
bytes read, not files another process later changes; this is not a filesystem
sandbox or a network-filesystem latency guarantee. Exit 0 means preparation
completed, not evidence validity, authenticity, completeness, or deployment approval.
Exit 2 means invalid input/policy/output or failed preparation. No artifact is
silently dropped to turn failure into success.

Review and retain the plan hash through an independent trusted channel before
accepting later inputs. Do not treat a supplier-supplied plan/hash pair as your
requirements. A file pin identifies bytes, not their author or trustworthiness.

```bash
dspy-security-bench proofrun verify-collection intake/plan.json --json \
  --expected-plan-file-sha256 "$OWNER_RETAINED_PLAN_SHA256"
```

For repeated-trial entries, set `minimum_trials` to an integer of at least two
(typically five or more under your protocol). For online repeated-family review,
set `offline` to false and supply your expected `attestation_repository` and
builder/runner requirements. Policies are never inferred from the evidence or
silently overridden by a collection-wide flag. Structural bundles cannot satisfy
online authentication requirements. The API is
`proofrun_collection.review_collection(path, expected_plan_file_sha256=...)`;
`proofrun_review.review_bundle_bytes(raw, policy=...)` supports services that
already retain the exact input snapshot.

Behavior and limits:

- The entire plan is validated before any referenced file is read or GitHub
  verification is attempted. Empty plans, policy-family mismatches, duplicate
  IDs, case-insensitive duplicate paths, and repeated file pins are rejected.
  Reusing one artifact in multiple slots is not supported and does not establish
  independent evidence.
- Paths are relative to the plan directory, using portable ASCII components and
  `.json` filenames. Absolute paths, URLs, traversal, Windows reserved names,
  symbolic links, observed Windows reparse points, and special files are rejected.
  Use a stable, owner-controlled local directory: this is not an OS sandbox
  against concurrent ancestor-directory replacement or a timeout for stalled
  network filesystems.
- Limits are 25 entries, 1 MB of plan JSON, 50 MB per artifact, and 100 MB of
  aggregate artifact input, plus at most a one-byte overflow probe per read.
  Every planned entry gets an outcome, including entries that cannot be reviewed
  within the budget. Read failures conservatively charge the attempted allocation.
- Exit 0 means every entry passed its selected review. Exit 1 means at least one
  valid entry did not pass eligibility/authentication, with no invalid entries.
  Exit 2 means invalid plan/input, pin/type mismatch, exhausted byte budget, or
  native verification failure. Invalid individual files do not suppress later
  outcomes; a successful majority cannot override a failure.
- Output includes the exact plan hash, per-entry expected/observed file hashes,
  expected bundle types, indexes, SHA-256 entry-ID fingerprints, native decisions,
  and counts. Private labels, paths, source values, and raw diagnostics are omitted.
  Hashes remain correlatable and are not anonymization or permission to publish.
- JSON output is one object on stdout after successful argument parsing, including
  invalid requests. There is no automatic output-file write, download, execution
  of submitted code, publication, or deployment. Online entries may perform the
  same GitHub attestation lookup as individual reviews.

Packaged schemas describe the [plan](../dspy_security_bench/schemas/proofrun-collection-plan.schema.json)
and [review](../dspy_security_bench/schemas/proofrun-collection-review.schema.json).
Native validation adds path/uniqueness rules and exact count/hash binding; schema
validation alone cannot establish these relationships or authenticity. Retain the
original artifacts and rerun against your original policy instead of trusting a
supplier's review JSON. Collection success is not proof that your requirements
are complete, that execution was independently reproduced, or that a deployment
is safe. All three authority flags remain false.

### Transfer an exact collection snapshot (on main)

Use `proofrun snapshot-collection` to assemble a supplier, internal assurance,
or independent-research handoff after an accountable owner has reviewed the
collection plan. Install a reviewed revision supporting this unreleased command.
The recipient uses the same `verify-collection` interface and the same plan pin;
there is no new archive or evidence format to trust.

```bash
# OWNER_PLAN_SHA256 must come from your independently retained approved plan.
# The parent directory must exist; handoff must not already exist.
dspy-security-bench proofrun snapshot-collection intake/plan.json \
  --expected-plan-file-sha256 "$OWNER_PLAN_SHA256" --out handoff --json

# On the recipient's machine, after an authorized transfer of the directory:
dspy-security-bench proofrun verify-collection handoff/collection-plan.json \
  --expected-plan-file-sha256 "$OWNER_PLAN_SHA256" --html > recipient-review.html
```

The command checks the mandatory plan pin and entire plan contract, then reads
each required artifact once. Every artifact must match its exact file pin, be
strict JSON, and declare the required family. It preserves whitespace, Unicode,
entry order, original relative paths, and every review policy. Copying does not
rerun native verification: even semantically invalid or ineligible evidence can
be faithfully copied, and the recipient's native review must still reject it.
Online policies remain online; snapshot creation never invokes `gh`, but a
recipient review may do so as specified by its plan.

All input snapshots must be admitted before output creation. Limits remain
1 MB for the plan, 25 required artifacts, 50 MB per artifact, and 100 MB of
aggregate artifact bytes. Snapshots are retained in memory, so these are input
budgets, not a process-memory ceiling. Missing files, linked/reparse artifact components,
invalid JSON, incorrect pins/types, or exhausted budgets produce exit 2 without
creating the destination. Unsafe plan paths already fail plan validation.
Additionally, paths that collide with one another as file/directory prefixes,
or with reserved `collection-plan.json`, are rejected case-insensitively before
artifact reads. Shared parent-directory spellings must also agree exactly:
`Folder/a.json` and `folder/b.json` cannot form a portable handoff. The command
never renames artifacts or edits the pinned plan.

The output directory must be new beneath an existing unlinked parent. Files are
exclusively created, with restrictive POSIX creation modes where supported;
deployment-owned access controls remain necessary. The unchanged plan is written
last. Exit 0 reports a completed copy, **not** approved or verified evidence.
An I/O failure returns exit 2 and can leave partial new files, including a partial
plan; inspect that directory and use a fresh destination for a retry. Existing
files are never overwritten and no recursive cleanup is attempted. This is not
an atomic/durable transaction or a race-proof filesystem sandbox: keep both
source and destination parents owner-controlled and stable during the operation.

The [snapshot receipt schema](../dspy_security_bench/schemas/proofrun-collection-snapshot.schema.json)
records observed/written counts, accepted artifact-byte totals, exact plan pins,
completion, and a zero-based failed entry index where available. Receipts omit
paths, entry labels, repository names, and raw diagnostics. An observed plan
hash may remain in a failed receipt; only `snapshot_complete: true` indicates
that this invocation completed the copy. Saved receipts do not authenticate
the files or substitute for recipient-side review.

**Snapshot contents are not redacted.** The directory contains the original
plan and complete artifact files, potentially including private metadata.
Review sharing permission and contents before transfer; this command never
uploads, signs, creates an archive, or approves disclosure. A plan and hash
delivered through the same untrusted channel do not establish owner approval.
The sender may lose access to the original files after the copy; recipients
still review the retained bytes, with missing or modified required files failing
normally. Requirement completeness and deployment approval remain owner duties.

Design rationale: SLSA's verification guidance separates consumer expectations,
artifact-digest matching, and provenance authentication. This handoff applies
that separation to collection transport; it does not establish a SLSA level or
implement a new SLSA verifier. See [SLSA: verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts).

### Human-readable HTML reviews (on main)

Use `--html` with either review command for a self-contained report suitable for
engineering, procurement, or governance review. It runs the same native checks;
it does not import a supplier's saved review as evidence. Install a reviewed
revision supporting this unreleased interface before using these examples:

```bash
dspy-security-bench proofrun verify supplier.json --offline --html \
  --expected-file-sha256 "$OWNER_FILE_SHA256" > artifact-review.html

dspy-security-bench proofrun verify-collection intake/plan.json --html \
  --expected-plan-file-sha256 "$OWNER_PLAN_SHA256" > collection-review.html
```

Use `--structural` for an individual structural bundle; collections retain each
entry's explicit policy. `--html`, `--json`, and `--junit` are mutually exclusive.
After argument parsing, stdout contains a complete report even for invalid
evidence or rejected plans. Argument-parser errors still go to stderr without a
report. Exit codes remain **0** (selected checks passed), **1** (requirements
unmet), or **2** (invalid or unreviewed). Preserve that exit status in CI and
retain reports on failures; do not add `|| true`. Shell redirection can overwrite
files before the command starts: choose fresh output paths that are distinct
from all input artifacts and plans.

The overview includes every required slot and separates integrity, eligibility,
and provenance. Offline provenance is **Not checked**, never authenticated.
Missing artifacts and exhausted budgets remain errors; invalid plans show an
explicit admission failure rather than an empty successful review. Expanded
details show fixed guidance, selected policy when available, and exact file,
bundle, repository, and entry-ID fingerprints. For slots rejected before native
review, consult the owner plan for policy details.

Open the file locally; no web server, scripts, network assets, or analytics are
required. The layout includes keyboard-operable details, a scrollable outcome
table, and print styling. All details start expanded; expand any collapsed
sections before printing. Text contrast has regression tests, but this is not
an accessibility certification.

Paths, entry labels, repository names, and arbitrary source diagnostics are
omitted. Fingerprints are still linkable; review organizational sharing policy
before distributing reports. HTML is unsigned presentation, not verified
evidence: regenerate from original artifacts and independently retained pins.
Neither a green decision nor a modified HTML page establishes deployment
approval, complete requirements, or independently reproduced execution.

### Export all report formats from one review (on main)

Use `--report-dir` when engineers need JUnit, reviewers need HTML, and automation
needs JSON from the **same invocation**. It is mutually exclusive with `--json`,
`--html`, and `--junit`. Install a reviewed revision supporting this unreleased
interface. The output parent must already exist, and the destination must be new:

```bash
dspy-security-bench proofrun verify supplier.json --offline \
  --expected-file-sha256 "$OWNER_FILE_SHA256" --report-dir artifact-reports

dspy-security-bench proofrun verify-collection intake/plan.json \
  --expected-plan-file-sha256 "$OWNER_PLAN_SHA256" --report-dir collection-reports
```

Use `--structural` for a structural individual bundle; the collection's explicit
entry policies are unchanged. Invalid destinations fail preflight before input
review or provenance lookup. A valid request invokes the native reviewer once,
then renders its source-redacted result into four files:

| File | Purpose |
| --- | --- |
| `review.json` | Complete native review decision, including failed outcomes |
| `review.html` | Human-readable presentation of that decision |
| `review.xml` | JUnit presentation of that decision |
| `manifest.json` | Exact SHA-256 hashes and byte sizes of the three reports, native exit code, and verifier version |

This does not multiply online provenance calls by the number of output formats.
Every format uses the same captured decision even if source files subsequently
change. Repeated offline exports from the same input path, bytes, policy, and
verifier are deterministic; a changed input path changes the JUnit scope identity.
No evaluation time, reproduction, approval, or independent witness is invented.

Stdout is one [export receipt](../dspy_security_bench/schemas/proofrun-report-export.schema.json),
not the review itself. `report_set_complete` describes **file export**, not
whether evidence passed. `native_exit_code` is null when review did not finish.
When export completes, the command preserves the native 0/1/2 exit code, so an
invalid plan or missing artifact can produce a complete report set and exit 2.
Rendering or storage failure also exits 2, with `report_set_complete: false` and
the native code retained if review finished. Check both fields, and retain
failed-run reports in CI without suppressing the command's nonzero status.

The [manifest](../dspy_security_bench/schemas/proofrun-report-manifest.schema.json)
is written last. The completed receipt pins its exact bytes and `review.json`;
file hashes can identify accidental modification or mixing after export. They
do not authenticate the reviewer or prevent someone from editing and rehashing
every file. Neither the manifest, JSON, HTML, nor JUnit is accepted as a substitute
for original evidence: recipients must rerun native review with independently
retained input pins. There is no saved-report approval or signature claim.

All outputs use exclusive creation; existing files and final links are never
overwritten. Directories and files request restrictive POSIX permissions where
supported. The shared snapshot output checks reject observed linked/reparse
parents, but require stable owner-controlled paths and appropriate local ACLs.
An interruption or I/O error can leave partial new files, including a partial
manifest; there is no automatic deletion or atomic/durable multi-file guarantee.
Inspect incomplete output and choose a fresh destination for retry. Render
failures occur before the directory is created. Retain the export receipt and
actual process status rather than inferring success from a filename's existence.

These reports omit artifact contents, input paths, repository names, and entry
labels. Fingerprints remain linkable. Review organizational sharing policies;
the command writes locally and does not upload, attest, or publish anything.

### JUnit results for existing CI (on main)

Both review commands accept `--junit` instead of `--json`. After normal argument
parsing, stdout contains one XML document even for invalid evidence or plans;
the process still exits 0, 1, or 2 according to the native decision. Ordinary
argument-parser errors remain stderr messages and do not produce XML.

```bash
dspy-security-bench proofrun verify supplier.json --offline --junit \
  --expected-file-sha256 "$OWNER_FILE_SHA256" > artifact-review.xml

dspy-security-bench proofrun verify-collection intake/plan.json --junit \
  --expected-plan-file-sha256 "$OWNER_PLAN_SHA256" > collection-review.xml
```

Use `--structural` for an individual structural bundle. Collection policy is
still selected per entry in the owner-reviewed plan. Shell redirection controls
file creation/overwrite; use fresh destinations when retaining earlier reviews.
Do not append `|| true` or otherwise discard the review process's nonzero exit.

| Native outcome | JUnit representation |
| --- | --- |
| Passes selected review | Passing testcase |
| Valid but ineligible, or provenance unverified | `failure` |
| Invalid/missing input, pin/type mismatch, or exhausted input budget | `error` |
| Invalid collection plan | One `plan-admission` error testcase |

Collections emit one testcase per required entry; unreviewed entries are never
reported as skipped. Suite counts come from the emitted cases. Names contain a
SHA-256 namespace derived from retained input/plan hashes (when available), policy, and the hashed CLI input
path, plus an ordinal for collection entries. Different inputs or policies do not
collapse under duplicate names; changed namespaces are not themselves evidence
of a security regression. Python renderers accept an optional `scope` string
that is hashed, not copied. Keep scope consistent when reviewing the same input
over time, and distinct when combining separate jobs with unreadable inputs.

Private input paths, entry labels, source metadata, and raw diagnostics are not
copied into the XML. Hashes remain correlatable. Public decision projections are
available in each testcase's `system-out`; suite properties use JSON-encoded
values. The format avoids testcase-specific properties and fabricated durations,
timestamps, or hostnames. It follows the common JUnit subset; test your server's
parser before adoption. Local tests verify XML structure and consumption by this
repository's CI diagnostic reader, not every hosted CI implementation.

After installing a reviewed version supporting this unreleased interface on a POSIX-shell runner,
Jenkins can retain the report even when the review step fails:

```groovy
pipeline {
  agent any
  stages {
    stage('Review required evidence') {
      steps {
        sh 'dspy-security-bench proofrun verify-collection intake/plan.json --junit --expected-plan-file-sha256 "$OWNER_PLAN_SHA256" > evidence-review.xml'
      }
    }
  }
  post {
    always {
      junit testResults: 'evidence-review.xml', allowEmptyResults: false
    }
  }
}
```

Keep empty-result acceptance disabled so a missing report remains visible;
see the [Jenkins JUnit step](https://www.jenkins.io/doc/pipeline/steps/junit/).
The hash variable must come from your independently retained owner policy.

For an already configured GitLab runner with the package installed:

```yaml
evidence_review:
  script:
    - dspy-security-bench proofrun verify-collection intake/plan.json --junit --expected-plan-file-sha256 "$OWNER_PLAN_SHA256" > evidence-review.xml
  artifacts:
    when: always
    reports:
      junit: evidence-review.xml
```

[GitLab's test-report documentation](https://docs.gitlab.com/ci/testing/unit_test_reports/)
notes that report display does not determine job status. Preserve the nonzero
command exit; uploading XML alone is not a gate. Upload only the intended report
under your organization's sharing policy, not a broad directory of source evidence.
JUnit export adds no attestation, new evaluation, or approval authority. It must
be generated by rerunning the native review, not trusted as a supplier-authored
replacement for the pinned plan and original artifacts.

### Retaining and interpreting review decisions

Decisions include the exact `input_file_sha256`, and `bundle_sha256` only when
native validity is established. They record the installed package version and
review policy. An explicit `--attestation-repo` is represented by SHA-256 of the
exact repository string's UTF-8 bytes in `policy.expected_repository_sha256`;
null means no explicit repository constraint. That hash is an informational policy
fingerprint, not an identity check. Keep the original repository setting in your
private pipeline configuration if you need to repeat an online lookup.

Submission notes, source URLs, repository names, file paths, provider outputs,
and raw exceptions are omitted. Hashes can still correlate known inputs, so this
projection is not anonymization or publication approval. Offline output is
deterministic for identical bytes, policy, and installed verifier. Online output
may change with availability or trust state and should be refreshed as needed.
No timestamp, self-signature, or claim of independent reproduction is invented.

The review document itself is unsigned. A well-formed document can be forged;
schema validation is not evidence verification. Rerun `review_bundle` against
the retained original bundle and your intended policy instead of trusting a
supplier-provided decision JSON. `review_is_attestation` and
`execution_reproduced` remain false, even when the underlying bundle's GitHub
provenance was verified.

### Preserve generated evidence

**On main after v0.19.0**, every ProofRun generation command (`run`, `control`,
`incident`, `source`, and `authority`) requires distinct new output files beneath
existing directories. This covers `--out`, `--report-out`, and `--card-out` where
supported. Create your artifact directory first. Existing files, directories in
place of files, hard-linked files, dangling links, and paths traversing symlinks
are rejected before any user agent/adapter factory runs. On systems where `/tmp`
is a symlink, use its real directory path or a directory in your checkout.

This intentionally replaces earlier overwrite behavior: assigning the same path
to a bundle and standalone report could silently replace the bundle, and reusing
an output could destroy retained evidence. Use a new run-specific directory or
filenames; do not overwrite evidence that has already been pinned or signed.
An output-layout failure exits 2 and performs no model or adapter execution.

Writes recheck paths and exclusively create files after execution, protecting
an existing final destination even if it appeared after preflight. JSON output
rejects nonfinite numbers before opening the destination. Multi-file output is
**not atomic**: if a later write fails, earlier files remain for inspection.
Preflight is not a reservation, a writable-disk guarantee, a budget estimate,
or protection against a hostile process replacing parent directories during
execution. Use a private, stable output directory. A late storage failure can
still occur after model costs have been incurred.

For policy-effectiveness evidence, use `proofrun control`. The bundle and card
are written before any configured statistical gate is enforced:

```bash
dspy-security-bench proofrun control \
  --agent myapp.security:build_agent \
  --policy policies/production.yaml \
  --policy-source "https://github.com/you/agent/blob/COMMIT/policies/production.yaml" \
  --trials 10 \
  --min-containment-lower-bound 0.70 \
  --submitter "@your-handle" \
  --agent-source "https://github.com/you/agent/tree/COMMIT" \
  --out control-evidence.json \
  --card-out control-evidence.svg
```

For authorization-conformance evidence, use `proofrun authority`:

```bash
dspy-security-bench proofrun authority \
  --adapter myapp.authority:build_adapter \
  --trials 10 \
  --min-lower-bound 0.70 \
  --submitter "@your-handle" \
  --adapter-source "https://github.com/you/agent/blob/COMMIT/myapp/authority.py" \
  --out authority-evidence.json
```

## Evidence ladder

| Tier | What is established | What is not established |
|---|---|---|
| `self_attested` | Content digest and fully recomputable statistics | Who executed the agent |
| `github_attested` | Exact bytes came from a named GitHub workflow, source commit, and hosted runner | Independence of the caller-controlled workflow |
| `trusted_builder` | The attested run used the versioned DSPy Security Bench reusable workflow | Independent observation of the model provider's response |
| `maintainer_reproduced` | Maintainers repeated the result and recorded the matching bundle digest | Generalization beyond the frozen scenarios |

`submissions/reproductions.json` is the content-addressed maintainer registry.
It references accepted bundle digests rather than mutable display names.
`submissions/attestations.json` separately records cryptographically checked
GitHub tiers. A declared workflow URL alone is displayed as “attestation
pending” until that digest is in the verified registry.

## Trust boundary and limitations

### Submission preflight for all five ProofRun families

`proofrun run`, `control`, `incident`, `source`, and `authority` validate submission
metadata before importing your agent/adapter factory, loading a mission pack,
policy or approval callback, or making model calls.
Supply a nonblank `--submitter`, credential-free HTTPS `--agent-source`
(`--adapter-source` for authority), and, for
control runs, a credential-free HTTPS `--policy-source`. Notes must be portable
UTF-8 text. Invalid metadata exits 2 without creating output files; diagnostics
identify contract fields without echoing supplied values.

When `GITHUB_ACTIONS=true`, the captured GitHub identity must be complete, including
repository/run identifiers, full commit and workflow SHAs, a `refs/` source ref,
and supported builder/runner labels. Incomplete GitHub metadata fails closed; it
does not silently fall back to a local claim. Fix the workflow context before
retrying. The provenance snapshot is taken once before user code runs and reused
in the resulting bundle. This is a declaration snapshot, not a trusted execution
boundary or proof that the agent cannot alter its own process.

All five Python bundle creators enforce the same metadata checks before report
replay. Native bundle verifiers also reject mistyped declarations before hashing
or replay: booleans/floats are not schema versions, null/numeric submitters are
not names, run identifiers are ASCII digit strings, and source URLs must not
contain credentials. Invalid metadata returns an invalid result without echoing
unknown field names or supplied values. Trial-policy arguments must be integers
of at least two; invalid caller policies raise `ValueError`.

Existing valid schema-v1 (no provenance) and schema-v2 formats are unchanged.
Older malformed declarations that were accepted through coercion now fail. Keep
original evidence for audit; correct declarations and create a new bundle from
the retained, valid report. Its digest changes, so obtain a new attestation rather
than reusing the old one. Neither rehashing nor correcting metadata authenticates
the original execution. Preflight does not guarantee that a later model call,
report verification, or output write will succeed.

### What the evidence establishes

ProofRun deliberately makes narrow claims:

- The attestation authenticates workflow provenance and exact evidence bytes.
- The bundle authenticates its own internal consistency through canonical
  hashing and offline recomputation.
- Secrets are never copied into provenance. Only a bounded set of public GitHub
  context fields is captured.
- A workflow cannot make a remote model provider independently observable. A
  malicious repository can substitute an agent or mock a provider before the
  trusted workflow calls it. Source review, provider-side receipts, confidential
  computing, and independent reproduction are complementary controls.
- Results describe repeated executions over five committed synthetic
  ProcureBench pairs. They do not estimate all procurement tasks and are not a
  legal, acquisition, safety, or regulatory certification.

The design follows GitHub's artifact-attestation model: an OIDC identity signs
an in-toto statement through Sigstore, and verification checks both the subject
digest and certificate claims. See GitHub's
[artifact attestation documentation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
for the platform trust model.

## Community evidence contracts

Place agent-only bundles under `submissions/impact/`, policy-effectiveness bundles
under `submissions/control/`, cyber-response bundles under
`submissions/incident/`, or MissionPack grounding bundles under
`submissions/source/`, then open a pull request. CI performs
offline recomputation for every bundle and performs online attestation
verification for schema-v2 bundles that claim GitHub provenance. The public
dashboard labels the evidence tier; it never renders a checksum as an identity
claim. Valid control evidence does not need a favorable score.

Before submitting:

```bash
dspy-security-bench proofrun verify submissions/impact/your-agent.json
dspy-security-bench proofrun verify submissions/control/your-agent-policy.json
dspy-security-bench proofrun verify submissions/incident/your-agent.json
dspy-security-bench proofrun verify submissions/source/your-agent.json
```

Use only synthetic inputs. Never include customer records, private prompts,
credentials, production tool outputs, or restricted acquisition information.

### Public registry intake boundaries (on main)

`python scripts/validate_impact_submissions.py` checks the nine committed
submission categories (`impact`, `control`, `incident`, `source`, `authority`,
`trace`, `causal`, `collective`, and `defense`) and both tier-metadata registries.
It invokes each category's native verifier and refuses a bundle filed under a
different type. This broader registry check is distinct from the five-family
ProofRun review CLI/API described above.

CI reads strict UTF-8 JSON objects and rejects duplicate keys, nonfinite numbers,
unpaired surrogates, excessive nesting/numeric tokens, symlinks in input paths,
and non-regular files. Limits are 1,000 submission candidates, 50 MB per bundle,
250 MB of discovered aggregate file sizes, and 5 MB per tier registry (decimal
bytes). Count/aggregate overflow rejects the batch; malformed individual inputs
do not prevent later candidates from being checked. Any rejected candidate or
registry entry makes the script exit 1; complete acceptance exits 0.

Safe relative filenames identify failures; source field names, values, malformed
filenames, and raw native/process diagnostics are withheld. GitHub attestation
lookup happens only after native validity and eligibility pass, and consumes the
same original byte snapshot. The script prints cryptographic acceptance only
after that lookup succeeds. It requires an already configured GitHub CLI identity
for online checks; no credentials or additional permissions are created by intake.

`submissions/attestations.json` references only bundles cryptographically accepted
during this run—not merely local valid/eligible results. Its exact root fields
are `schema_version` (integer 1) and `attestations`. Each lowercase SHA-256 key
maps to exactly six nonempty string fields: `evidence_tier`, `verified_by`,
`verified_at`, `run_url`, `source_commit`, and `signer_workflow`. UTC timestamps
ending in `Z` and credential-free HTTPS run URLs are required. Tier, commit,
and run URL must match the authenticated bundle; the trusted-builder workflow
must match the project's fixed workflow identity. Caller-workflow signer labels
and human reviewer names remain maintainer declarations, not additional identity
proofs.

`submissions/reproductions.json` has exact root fields `schema_version` (integer
1) and `reproductions`. Each accepted bundle digest maps to exactly three
nonempty strings: `reproduced_by`, `run_url`, and `created_at`, with the same
URL/time rules. This validates linkage and record structure; it does not perform
or independently authenticate the claimed reproduction. Maintainer review is
still required before publishing either registry.

Use a stable, trusted checkout for CI. These checks reject static linked inputs;
they are not an OS sandbox, an atomic snapshot of an entire checkout, or protection
against malicious code modifying files concurrently under the same user account.

### Dashboard publication gate (on main)

Every community-evidence row is now admitted by its full native verifier before
projection into the dashboard. A self-rehashed aggregate with missing or
contradictory trials is not sufficient. Strict JSON intake rejects malformed
files and linked inputs; the standalone renderer skips those rows. Malformed
attestation/reproduction records cannot upgrade a tier, and local provenance
cannot receive a GitHub-attested label. CI and site rendering share the same
typed registry-record checks.

The Pages workflow runs the complete submission/registry gate **before** data
generation and artifact upload. Unlike the standalone renderer's safe omission
behavior, an invalid submission or registry makes publication fail. GitHub claims
must pass online verification during this gate; local registry eligibility alone
never enters its authenticated-bundle map. Both submission CI and Pages provide
the normal workflow token only to this verification step, with `contents: read`
and `attestations: read`. The Pages build has no write/OIDC permission; Pages
configuration and deployment use a separate job with the required Pages/OIDC
write permissions. No personal token is stored in the repository.

The renderer remains offline and needs only Python's standard library and
PyYAML, not model-provider SDKs. Reading a structurally valid registry record
locally is not itself cryptographic authentication: publish through the gate,
using a reviewed verifier/workflow implementation. Maintainer reproduction
records still require human review and do not cause independent execution.
Tests exercise malformed metadata and simulated verification responses; a local
test pass does not assert that a live GitHub deployment or signature lookup ran.
