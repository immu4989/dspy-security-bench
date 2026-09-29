# Review repeated scans without hiding incomplete trials

**On main; not in the published v0.19.0 package.** `scan study` is an offline
review of a declared, fixed-scope series of retained scans. It does not schedule
or execute models. Use it to see intermittent case failures and retain missing
attempts when reviewing an agent, defense, or configuration with its owner.

The scientific boundary matters: [NIST AI 800-3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.800-3.pdf)
distinguishes performance on a fixed benchmark from generalization to a larger
item population, with different assumptions and uncertainty. This feature
reports **descriptive observations only**. It does not implement NIST's
estimators, assume independent trials, infer pass-at-k probabilities, or assign
confidence intervals from correlated case counts.

## Try a fictional review first

```sh
dspy-security-bench scan study demo --out fictional-study
```

Open `fictional-study/review.html` directly in a browser. It needs no server,
credentials, remote assets, or model execution. Six deterministic files include
the local manifest, two source inputs, report JSON, HTML, and replay instructions.
The five invented trials deliberately include one missing run, one execution
error, and a repeated source digest. None of these are measured model results.
Existing destinations are refused; unexpected I/O failures may leave partial
files for inspection rather than deleting them.

## Declare a study before collecting its trials

Start with verified pilot evidence from an authorized scan. Derive the scope,
gate-policy identity, and baseline identity from that evidence:

```sh
dspy-security-bench scan study init pilot-evidence.json \
  --study-id reviewed-agent-candidate --trials 3 --out study-manifest.json
```

This creates a **new** manifest. All three trials start as `missing`; the pilot
is not silently counted as a study trial. Review the plan, predeclare collection
and stopping rules, and independently retain the printed `plan_sha256` before
collecting outcomes. A digest alone does not prove when a plan was created;
use your own timestamped change-review/provenance system where needed.

Collect each trial in a separate, owner-authorized execution with the same
scope, gate policy, and baseline. Keep fresh evidence under the manifest's
directory. Record one outcome into a **new manifest revision**:

```sh
dspy-security-bench scan study record study-manifest.json \
  --trial trial-001 --status complete --evidence trial-001.json \
  --expected-plan-sha256 "$REVIEWED_STUDY_PLAN_SHA256" --out study-revision-1.json

dspy-security-bench scan study record study-revision-1.json \
  --trial trial-002 --status execution_error \
  --expected-plan-sha256 "$REVIEWED_STUDY_PLAN_SHA256" --out study-revision-2.json
```

Paths passed to `--evidence` are relative to the input manifest, not the shell's
working directory. The new manifest must be alongside the original so all
relative references retain their meaning. The command verifies every complete
source against the unchanged plan and computes the new source's digest. It
does not run an agent or make failing evidence pass. Exit 0 means recording
succeeded, not that study requirements are met; use `review --fail-on-shortfalls`.

Only a `missing` trial may transition to `complete` or `execution_error`.
Already-recorded attempts cannot be overwritten, including with identical
evidence. Preserve errors; any additional attempted run needs a separately
reviewed plan rather than replacing an unfavorable attempt. Keep previous
manifest revisions and authorized provenance. This is local bookkeeping, not
an append-only log, timestamp authority, or proof that every attempt was disclosed.
Directly edited manifests remain supported and are checked during review, but
their editing history cannot be reconstructed by this tool.

For integrations that construct manifests directly, a complete declaration is:

```json
{"trial_id":"trial-001","status":"complete","evidence":"trial-001.json","evidence_sha256":"<retained canonical evidence digest>"}
```

The placeholder must be replaced with that source's lowercase 64-character
`evidence_sha256`, not a file-byte digest. Source paths must be relative, beneath
the manifest directory, without `..`, absolute paths, or symlinks. Paths are not
exported into study reports. Keep identifiers content-free and review them
before sharing; this is not anonymization or a secret scanner.

Every planned ID must remain present exactly once. Other valid declarations are:

```json
{"trial_id":"trial-002","status":"execution_error"}
{"trial_id":"trial-003","status":"missing"}
```

No exception text, prompt, or provider payload belongs in those declarations.
Preserve authorized private incident details separately. Unreadable or invalid
evidence for a purportedly complete trial is an **invalid review**, not an
automatically reclassified missing trial. Do not discard unfavorable attempts
or replace them until they pass. Any rerun/stopping policy needs prior owner
review; this tool cannot detect attempts that were never disclosed.

## Recompute the review

```sh
dspy-security-bench scan study review study-manifest.json \
  --expected-plan-sha256 "$REVIEWED_STUDY_PLAN_SHA256" \
  --json study-review.json --html study-review.html --fail-on-shortfalls

dspy-security-bench scan study review study-manifest.json \
  --expected-plan-sha256 "$REVIEWED_STUDY_PLAN_SHA256" \
  --verify study-review.json --fail-on-shortfalls
```

The plan pin is optional but recommended for an independently reviewed study.
Changed scope, policy, baseline, trial list, or study identity breaks it. Every
complete source is natively reverified, matches its retained evidence digest,
and must match the plan's scope, gate policy, and baseline exactly. The same
plan is not suitable for pooling different models or benchmark versions.

Exit codes:

- **0:** valid review; without the policy flag this includes unmet requirements.
- **1:** with `--fail-on-shortfalls`, at least one planned trial is incomplete or
  at least one complete scan did not meet its original requirements.
- **2:** invalid input, source evidence, plan pin, recomputation, or output.

Valid but nonpassing reviews are still written. Outputs require new files and
existing parents; archived reports are never overwritten. Exact replay compares
the full report, including its cases, statuses, source digests, and limitations.
The [schema](../dspy_security_bench/schemas/scan-study.schema.json) supports
structural intake for reports and its `plan`/`manifest` definitions; it is not a
substitute for semantic verification.

The optional HTML page prioritizes coverage and missing/error states before
conditional rates. It shows every trial and up to 50 cases, placing varied and
failing cases first, with omissions labeled. Retain full JSON for all cases.
HTML has no scripts, external fonts/assets, or analytics; keyboard-scrollable
tables and a print layout support offline review. It is a presentation, not a
verifier. Multiple outputs are preflighted but not a filesystem transaction:
an unexpected I/O failure can leave a partial output set.

## Read the results correctly

### Share a self-contained, replayable bundle

```sh
dspy-security-bench scan study bundle study-revision-2.json \
  --expected-plan-sha256 "$REVIEWED_STUDY_PLAN_SHA256" --out study-bundle.json

# Recipient: no original directory, manifest, network, or model access needed.
dspy-security-bench scan study verify-bundle study-bundle.json \
  --expected-plan-sha256 "$REVIEWED_STUDY_PLAN_SHA256" \
  --expected-bundle-sha256 "$INDEPENDENTLY_RETAINED_BUNDLE_SHA256" \
  --html verified-review.html --fail-on-shortfalls
```

The bundle contains the exact study plus each distinct native source once,
indexed by its evidence digest. All trial declarations remain, including
repeated sources, missing trials, and errors. Source-file paths are omitted.
Identifiers and outcomes are **not anonymized**; obtain owner approval before
sharing. No raw prompts or outputs are introduced by bundling.

Both commands replay all sources and the derived report. Missing/extra sources,
false summaries, altered limitations, and invalid pins fail verification even
when outer hashes have been recomputed. Optional independently retained plan
and bundle pins detect substitution; a hash sent alongside the file on the same
untrusted channel does not establish authenticity. Bundles are not signed
attestations or proof of when or whether execution occurred.

Output files must be new. Input/output bundles are limited to 50 MB; a manifest
whose sources fit the input budget may still produce an oversized bundle after
including its report. Such an export is refused, never silently truncated.
`--fail-on-shortfalls` returns 1 for valid but incomplete/nonpassing studies,
after writing a requested bundle or HTML. Invalid input returns 2. The
[bundle schema](../dspy_security_bench/schemas/scan-study-bundle.schema.json)
references the sibling study/evidence schemas; register all three for offline
structural validation. Native verification is still required.

### Observe study revisions without running agents

Portable bundles are a native `scan-study` kind for ContinuousProof:

```sh
dspy-security-bench watch baseline study-bundle.json --label reviewed-study \
  --out study-snapshot.json
dspy-security-bench watch verify study-snapshot.json --evidence study-bundle.json
```

Snapshots keep coverage and execution-error fractions separate from conditional
security, utility, and joint rates. The plan and completed-trial roster are
identity-bound. Changing the observed subset requires review regardless of
scalar thresholds. With no complete trials, outcome rates are absent rather
than fabricated; moving to an observed study changes metric coverage and cannot
be compared as if both snapshots measured the same quantities. Repeated-source
changes also require review rather than being called better or worse.

Unchanged evidence can be `within_threshold` while still having unmet study
requirements. Observe-only status is not approval, a matched-case causal
comparison, or an independent-execution claim.

### Interpret descriptive outcomes

The report includes planned/complete/missing/error trial counts, observed and
planned case-trial counts, and per-case successes, failures, observed rates, and
whether both outcomes occurred. Three axes stay distinct:

- security resistance;
- useful task completion; and
- **secure and useful in the same case-trial**, computed from both binary bits.

Rates condition on **complete trials only**. Missing/error runs are not assigned
binary outcomes. With no complete trials, rates are `null`, not zero or one.
An apparently good conditional rate can coexist with an incomplete, nonpassing
study. There is no imputation, denominator reduction hidden from the report,
or extrapolation to production reliability.

`study_requirements_met` means all planned trials completed and each met its
original scan requirements. It does not mean every case succeeded or every
outcome was stable: that depends on the original thresholds. Review varied
cases even if the gate passes. Security and useful completion do not compensate
for each other, and the joint axis is descriptive rather than a new gate.

Repeated evidence digests are grouped explicitly. Identical observations can
arise from genuinely distinct deterministic runs or copied evidence; the
content-minimal source cannot distinguish them. Different digests also do not
prove independent execution. Retain run provenance, configuration/code identity,
model/version information, seed and environment controls separately.

The study supports 2–100 planned trials, at most 100,000 planned case-trial
observations, a 50 MB manifest, and **50 MB combined source files**. These bounds
are intake limits, not a provider budget or execution sandbox. Shared-tool and
shared-case dependence, optional stopping, evaluator error, and selection bias
are not statistically corrected. No output is a certification or deployment
approval. See [scan evidence](scan-evidence.md) for execution and privacy limits.
