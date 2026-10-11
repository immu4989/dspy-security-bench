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

All five bundle families use bounded strict JSON intake: at most 50,000,000
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

### Submission preflight for procurement runs

`proofrun run` and `proofrun control` validate submission metadata before importing
your agent factory, loading a policy or approval callback, or making model calls.
Supply a nonblank `--submitter`, credential-free HTTPS `--agent-source`, and, for
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

The Python `create_submission_bundle` and `create_control_submission_bundle`
functions enforce the same metadata checks before report replay. Their existing
schema-v1 (no provenance) and schema-v2 formats are unchanged. This metadata
preflight currently covers these two procurement families, not the `incident`,
`source`, or `authority` metadata contracts. It does not guarantee that a later
model call, report verification, or output write will succeed.

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
