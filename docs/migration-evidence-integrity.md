# Migrating to the evidence-integrity improvements on main

These changes are currently in source, not a new published release. Review them
before upgrading a pinned organizational installation. No published model scores
have been recalculated or revised by this work.

## Scanner behavior changes

- Missing baseline cells fail by default. Explicitly set
  `gate.require_baseline_coverage: false` only for informational comparisons.
- Newly generated CLI baselines bind the resolved task scope. Legacy rate-only
  baselines warn that scope is unverified. Create a new reviewed baseline for
  a genuinely changed experiment rather than weakening the check.
- Current scans use `complete-binary-observations-v2`: exceptions escaping task
  execution/evaluation become execution errors, not binary attack outcomes.
  Older v1 scope-bound baselines deliberately do not match; preserve them and
  create a newly reviewed baseline. Cached AgentDojo result reuse
  (`force_rerun=False`) is rejected because those entries do not establish this
  error-accounting contract. Offline `scan verify` remains available for retained
  v1 evidence without relabeling it as v2.
- Empty results, missing observations, nonbinary outcomes, invalid rates/counts,
  and incomplete requested matrices produce errors, not favorable defaults.
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

## Suggested upgrade procedure

1. Pin the currently deployed revision and preserve original evidence and policies.
2. Review the [Unreleased changelog](../CHANGELOG.md#unreleased) and these behavior changes.
3. Install the candidate in a separate virtual environment and run offline fixtures.
4. Generate a no-model `scan --plan-json` artifact; review scope and gate settings.
5. Recompute a small authorized sample and inspect missing/invalid states explicitly.
6. Approve and pin the candidate revision through your own change process.

The new supplier and portfolio workflows reduce repetitive review work; they do
not authenticate suppliers, assess the truth of every assertion, certify an
organization, or authorize procurement or deployment.
