# Upgrade a scan workflow without losing its evidence

**For the Unreleased main branch, not the published v0.19.0 package.** Pin a
reviewed source commit. Do not overwrite archived inputs, reports, or baselines
while upgrading. Keep the old revision and dependency lockfile alongside them.

## Three versions with different jobs

| Field | What it identifies | Upgrade action |
| --- | --- | --- |
| Plan `protocol_version`: `scan-plan-v2` | Reviewed execution scope, agent selection, gate, baseline, and configured task budget | Regenerate and independently review the plan. An old v1 digest is not a valid v2 approval pin. |
| Scope `measurement_protocol`: `complete-binary-observations-v2` | Fresh execution with escaping task/evaluation exceptions separated from binary scores | Re-run authorized before/after systems under the same protocol to make a matched comparison. Do not relabel old cache entries. |
| Evidence `protocol_version`: `scan-evidence-v1` or `scan-evidence-v2` | The frozen evidence/replay output contract | Security-only policies remain v1; an explicit utility floor uses v2. Both are replayable. Evidence version alone does not determine the measurement protocol. |

A v1 evidence file can contain the new measurement protocol. Conversely, changing
an evidence version string does not upgrade the quality of its observations.
Never edit protocol labels or rehash historical files to make them comparable.

## Before authorizing a new run

1. Replay retained evidence with `scan verify`. Success means the report
   recomputes; it does not authenticate execution or prove the observations true.
2. Check your historical baseline's scope. A scope-bound baseline from another
   measurement protocol cannot be used as though it were a current measurement.
   Keep it as an archive; capture a new baseline using the reviewed current code.
3. Review the current plan in a new output file:

   ```sh
   dspy-security-bench scan --config .dspy-security-bench.yaml \
     --max-task-runs 100 --plan-json reviewed-plan.json
   ```

   `100` is an example owner-selected task budget, not a recommendation. It
   counts scored and auxiliary task invocations, not provider requests, tokens,
   dollars, tool actions, or time. Plan-only output is inspectable even when a
   budget or sample requirement would block execution; inspect its findings.
4. Independently retain the plan's `report_sha256`. After authorizing the scope,
   model costs, and test-tool access, supply it as `--expected-plan-sha256` for
   the actual scan, retaining the same budget/configuration. A changed plan is
   refused before agent construction. A pin does not bind imported code bytes,
   secrets, or provider-side changes; retain those controls separately.
5. Use fresh `--evidence-json` destinations. An execution failure must not be
   replaced with a zero, a pass, or an empty answer to obtain a completed report.
   Preserve a private incident record and investigate before another paid run.

Do not point the benchmark at production write-capable tools. The task budget
and plan pin are preflight controls, not a sandbox or a runtime kill switch.

## Review CI exit-code assumptions

| Command | Exit 0 | Exit 1 | Exit 2 |
| --- | --- | --- | --- |
| `scan verify FILE` | Evidence recomputes, even with unmet requirements | Not used without the policy flag | Invalid or unreadable evidence |
| `scan verify FILE --fail-on-shortfalls` | Evidence recomputes and requirements are met | Valid evidence has unmet requirements | Invalid or unreadable evidence |
| `scan compare BEFORE AFTER` | Valid matched comparison, even with new failures | Not used without the policy flag | Invalid evidence or incompatible scope |
| `scan compare BEFORE AFTER --fail-on-regression` | New-failure allowances are met | At least one allowance is exceeded | Invalid evidence or incompatible scope |

For executed scan reports, use `requirements_met` to answer whether the declared
requirements were met. Legacy `passed` and the process exit reflect enforcement:
`fail_on: never` can permit an unmet requirement without making it satisfied.
Execution/preflight errors remain errors; non-blocking policy is not permission
to execute an infeasible plan.

Matched comparison does not approve the original scans. Two unchanged failing
scans can meet a no-new-failures allowance. Review both original requirement
outcomes, source policy changes, and new security/utility failures separately.
Adding `min_utility` does not change an old evidence file's policy retroactively.
Wilson bounds and minimum sample gates also do not establish independent cases,
population generalization, or significance for a before/after comparison.

## Credential-free rehearsal

Run `dspy-security-bench scan demo --out fictional-upgrade-review`. Its README
provides replay commands with expected exit codes **0, 1, 0, 1**; its offline
HTML explains how unchanged totals can conceal newly failing cases. These are
invented observations, not an approved baseline or measured model results.

Continue with [capture and matched comparison](scan-evidence.md),
[CI policy configuration](ci.md), and [release verification](releasing.md).
