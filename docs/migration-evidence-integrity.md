# Migrating to the evidence-integrity improvements on main

These changes are currently in source, not a new published release. Review them
before upgrading a pinned organizational installation. No published model scores
have been recalculated or revised by this work.

## Scanner behavior changes

ContinuousProof drift direction is now defined by explicit native metric paths.
Earlier substring inference could classify increases in `harmful_outcomes` or
`leakage_canary_hits` as improvements. Unknown metric changes now require review
regardless of the numeric regression allowance. Typed identity and field-presence
changes also require review. Source snapshots retain their original format, but
affected drift/controller reports must be regenerated from retained evidence;
preserve old artifacts and their original tool revision for historical review.

- Missing baseline cells fail by default. Explicitly set
  `gate.require_baseline_coverage: false` only for informational comparisons.
- Newly generated CLI baselines bind the resolved task scope. Legacy rate-only
  baselines warn that scope is unverified. Create a new reviewed baseline for
  a genuinely changed experiment rather than weakening the check.
- By default, current scans use `complete-binary-observations-v2`: exceptions escaping task
  execution/evaluation become execution errors, not binary attack outcomes.
  Older v1 scope-bound baselines deliberately do not match; preserve them and
  create a newly reviewed baseline. Cached AgentDojo result reuse
  (`force_rerun=False`) is rejected because those entries do not establish this
  error-accounting contract. Offline `scan verify` remains available for retained
  v1 evidence without relabeling it as v2.
- Optional supplied-tool admission limits use a distinct v3 measurement scope
  with the exact per-task limit. See [tool-call budgets](tool-call-budgets.md)
  before comparing or replacing scope-bound baselines.
- Empty results, missing observations, nonbinary outcomes, invalid rates/counts,
  and incomplete requested matrices produce errors, not favorable defaults.
- The built-in LiteLLM agent no longer converts a failed final-answer provider
  call into an empty answer. That failure propagates to execution accounting.
  Malformed, duplicate-key, non-object, nonfinite, or oversized tool arguments
  produce error feedback without executing a tool with substituted defaults.
  The tool loop can recover on a later valid call; rejected attempts remain
  identifiable as errors in its trace. Valid tool arguments still execute the
  supplied callable. This is not a tool sandbox or a full JSON Schema validator.
- New `min_runs` and `statistic: wilson_lower` gates are opt-in. Point estimates
  remain the default. Wilson evaluation requires measured integer counts;
  infeasible scopes stop before agent construction. See the CI guide for the
  fixed-benchmark assumptions and per-cell, two-sided interval interpretation.
- Configuration rejects duplicate YAML keys, unknown settings, and incorrectly
  typed values. Correct misspellings and quote only values intended as strings.
- Output paths cannot collide or overwrite input configuration/comparison
  baselines. Create output directories before running. Explicit baseline updates
  still use `--write-baseline`.

The runner previously defaulted an absent attack outcome to attack failure.
That path is now rejected. This is an input-handling correction; it does not by
itself establish that any particular historical published run contained missing
outcomes. Historical claims require checking their retained raw evidence.

See the [CI guide](ci.md) for scope-bound baselines, planning, exit codes, and
the distinction between missing evidence and observed injection success.

## Evidence parsing and signed statements

Native AuthorityTwin, TraceProof, and ScheduleProof checks reject boolean
schema versions and type-coerced derived outcomes. Authority reports, pairs, and
cases reject undeclared fields. TraceProof report severities must match their
frozen rule IDs, even if a modified finding and report have been rehashed, and
reported trace/span counts must be bounded positive integers. These checks do
not authenticate observations or reconstruct omitted source traces. Keep your
original artifacts and fix their producers; do not merely rehash invalid reports.

The shared strict JSON reader is used by AgentBOM, AssuranceLedger, and the
additional evidence command families listed in the Unreleased changelog.
Duplicate members, invalid Unicode, non-finite numbers, and excessive nesting
are rejected. This is not a claim that every JSON/YAML parser in the repository
has been replaced.

Numeric JSON tokens are limited to 128 characters before integer/float conversion,
including signs, decimal points, and exponent text. This is a local intake limit,
not a general JSON-standard limit; it preserves ordinary counts and rates while
rejecting pathological numeric literals independently of interpreter settings.
The [Python JSON documentation](https://docs.python.org/3/library/json.html)
describes resource risks from untrusted JSON and the interpreter's integer
conversion guard. File-byte and nesting limits remain separate. Floating-point
values retain ordinary Python rounding semantics; this is not decimal-exact
arithmetic or a complete resource-isolation boundary. Do not edit a signed
payload to shorten a number—obtain a corrected statement from its owner.

Signed review/recovery statements are limited to 1 MB decoded bytes and must
be unambiguous UTF-8 JSON objects. An oversized or ambiguous signed statement
must be corrected and re-signed by its authorized owner; do not mutate the
payload and expect the old signature to remain valid.

## AI disclosure reports and packs

Regenerate affected AI disclosure evidence from the independently retained
original inputs before exact verification:

- absent required component classes now produce missing-field findings;
- SPDX license combinations and exact standard license individuals are recognized;
- abstract license types and extra invalid license relationships do not satisfy
  the exactly-one relationship check;
- new portfolio packs include the complete `review.html` presentation.

Old report hashes may no longer recompute after these corrections. Keep old
evidence and the tool revision that produced it for historical review; never
silently replace an archived attestation or its pinned digest. Compare old and
new outcomes and record why they differ.

## Procurement evidence and public review

These changes are **on main after v0.19.0**, not a claim about the published
package. Preserve your original evidence, signatures, pins, and generating tool
revision before testing the candidate installation.

| Surface | What changed | Upgrade action |
| --- | --- | --- |
| RepeatTwin and control native verification | Boolean/count aliases, contradictory case scoring, altered BoundaryDiff, and inconsistent embedded control summaries are rejected | Replay retained sources; investigate invalid producers instead of merely recomputing hashes |
| Retained procurement JSON | Duplicate keys, invalid Unicode, nonfinite values, numeric tokens over 128 characters, excessive nesting, and files over 50 MB are rejected | Request unambiguous bounded originals; do not silently rewrite signed evidence |
| Reported usage | Invalid optional metadata is separated from task outcomes; overflowing subtotals remain unknown | Review per-field coverage; do not treat partial totals or deltas as a billing comparison |
| Control evidence cards | The retained confidence level and conditional sample counts replace a hard-coded 95% label | Regenerate affected SVGs from valid retained bundles; preserve previously shared versions with a correction note |
| Bundle CLI status | Invalid evidence prints `INVALID`; valid evidence failing registry rules prints `NOT ELIGIBLE` | Both still exit 1; update parsers that incorrectly treated these as one state |
| Sharing inventory | A new source-bound inventory can be generated and replayed offline | Review source contents locally; a successful inventory is not permission to publish |

Valid engine-generated report formats and hashes have not been relabeled by the
typed-verification fixes. Count fields require integer representations; boolean
flags require booleans. Integer spellings of real-valued rates remain allowed.
Submission envelopes now also require their declared metadata fields and reject
unknown fields. A numeric submitter or producer value is not coerced to text;
bundle schema versions must be integers, timestamps must be UTC strings ending
in `Z`, and GitHub run/repository identifiers must be ASCII-digit strings.
Reference URLs must be HTTPS, have a host and valid port, and contain neither
embedded credentials nor raw whitespace. This checks structure, not whether a
site is trustworthy, reachable, or authoritative. It does not detect secrets in
otherwise valid metadata. The native API's `minimum_trials` must be an integer
of at least two; command-line defaults remain unchanged.
An artifact accepted by an older permissive verifier is not automatically valid
under the corrected one. A consistent fabrication may still pass: native replay
does not authenticate execution, replay actual tool effects, validate provider
billing, or establish the truth of declared synthetic exposure.

### Run the procurement upgrade exercise

From the candidate source installation, in a directory where
`procurement-upgrade-check` does not already exist, run each command separately:

```sh
dspy-security-bench impact review-demo --out procurement-upgrade-check
dspy-security-bench impact control-submission-verify procurement-upgrade-check/bundle.json
dspy-security-bench impact sharing-review procurement-upgrade-check/bundle.json --verify procurement-upgrade-check/sharing-review.json
dspy-security-bench impact control-submission-verify procurement-upgrade-check/invalid-bundle.json
```

Expected exits: **0, 1, 0, 1**. The second command is valid but ineligible reference
evidence, not a failed execution. The last deliberately has a boolean event index
despite matching recomputed hashes. It must be invalid. Do not join the commands
with `&&`: the expected nonzero exits would stop the exercise early. No provider
credentials or production systems are used, and nothing is published.

Next, copy a small authorized set of **your own retained artifacts** into a private
review area and run the corresponding native verifier. Keep successful,
ineligible, and invalid cases separately. Record changed outcomes and their
explanation before changing organizational pins. Do not post failed artifacts
to public issues if they contain private model responses, errors, tool arguments,
policy details, or identifiers.

### Do not interchange the different digests

| Digest | Content it binds |
| --- | --- |
| A ControlTwin/RepeatControlTwin report's `report_sha256` | The report without that self-digest field |
| A submission bundle's `report_sha256` | The complete embedded report, including any embedded self-digest |
| A submission bundle's `bundle_sha256` | The bundle without that self-digest field |
| A sharing review's `source_sha256` | The complete canonical input object, including embedded digest fields |
| A raw-file checksum or signed-file identity | Exact bytes; JSON whitespace can matter |

Use the digest requested by the specific verifier. For
`impact sharing-review --source-sha256`, retain the whole-source pin independently.
Copying it from the review being checked does not establish independent trust.
Editing or redacting source evidence can invalidate signatures and native replay;
keep originals privately and produce a new authorized artifact when needed.

Matched scan comparisons have a separate opt-in change: supplying
`--max-new-joint-failures` produces a v2 comparison with an additional
secure-and-useful allowance. Omitting it preserves v1 comparison output. Replay
must use the independently selected allowances, including the joint allowance
for v2; do not infer approval policy from an untrusted report. See the
[scan evidence guide](scan-evidence.md) and
[procurement sharing review](impact-twin.md#review-retained-content-before-sharing).

## Suggested upgrade procedure

ProofRun generation now refuses existing or colliding output destinations before
agent/adapter construction across all five generation commands. Create parent
directories yourself and use new run-specific filenames for the bundle, optional
standalone report, and card. Symlink traversal is refused, and exclusive final
creation prevents truncating a destination created after preflight. This is a
deliberate change from implicit parent creation and overwrite behavior; see
[ProofRun output preservation](proofrun.md#preserve-generated-evidence) for race,
partial-output, and storage-failure limits.

1. Pin the currently deployed revision and preserve original evidence and policies.
2. Review the [Unreleased changelog](../CHANGELOG.md#unreleased) and these behavior changes.
3. Install the candidate in a separate virtual environment and run offline fixtures.
4. Generate a no-model `scan --plan-json` artifact; review scope and gate settings.
5. Recompute a small authorized sample and inspect missing/invalid states explicitly.
6. Approve and pin the candidate revision through your own change process.

The new supplier and portfolio workflows reduce repetitive review work; they do
not authenticate suppliers, assess the truth of every assertion, certify an
organization, or authorize procurement or deployment.
