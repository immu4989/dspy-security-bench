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
directory. Update only each trial declaration in the manifest, for example:

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
  --json study-review.json --fail-on-shortfalls

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

## Read the results correctly

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
