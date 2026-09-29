# Review a proposed gate without rerunning the agent

**On main; not in published v0.19.0.** `scan policy` answers “would these same
retained observations meet this proposed requirement?”—not “did the agent
improve?” This is explicitly **post-hoc policy-only decision analysis**.

## Copy, review, and retain the proposal

```sh
dspy-security-bench scan policy init retained-scan.json \
  --expected-source-sha256 "$RETAINED_SCAN_SHA256" --out proposed-policy.json
```

Edit the policy deliberately with the accountable owner. For example, add
`"min_joint_success": 0.75` to inspect a same-pair secure-and-useful floor.
Keep required fields. Unknown keys, duplicate JSON members, nonfinite values,
boolean numeric aliases, and invalid combinations are rejected. Unused optional
floors should be omitted, not explicitly null.

```sh
dspy-security-bench scan policy review retained-scan.json \
  --policy proposed-policy.json --expected-source-sha256 "$RETAINED_SCAN_SHA256" \
  --out policy-review.json --html policy-review.html --fail-on-shortfalls

dspy-security-bench scan policy verify policy-review.json \
  --expected-source-sha256 "$RETAINED_SCAN_SHA256" \
  --expected-review-sha256 "$RETAINED_REVIEW_SHA256" --fail-on-shortfalls
```

The optional HTML opens locally without scripts, remote assets, or a server.
It puts the post-hoc warning above both verdicts, shows every policy setting,
and previews up to 50 cell-requirement rows with changed verdicts first and
omissions labeled. Keyboard-scrollable tables and print styling support review
on narrow screens. `verify --html NEW_PAGE` can regenerate the same presentation
only after native verification. Keep the portable JSON for all findings and
source replay; the HTML itself is not a verifier. Multiple output destinations
are preflighted together, but writes are not a filesystem transaction.

The source is natively verified. The portable review retains the exact original
evidence, proposed policy, recomputed report, verdict summary, and a digest. A
recipient needs only this file: no model, credentials, original directory, or
network access. Its distinct `scan-policy-review-v1` type cannot be passed to
`scan verify` as if it were a new executed scan. Original files are untouched.

Scope and primitive binary outcomes never change. Joint counts use the original
paired bits, not a product of marginal rates. Regression proposals reuse only
the baseline already embedded in the source; an absolute source cannot invent
a regression baseline. A regression source may explicitly switch to absolute
policy while retaining its original baseline inside unchanged source evidence.

## Exits and limits

- **0:** valid copy/review/recomputation; without the shortfall flag this may
  include proposed requirements that were not satisfied.
- **1:** with `--fail-on-shortfalls`, proposed requirements are unmet. A valid
  review is still written, even when the proposed enforcement is `never`.
- **2:** invalid input, pin, native replay, or output; no successful review.

Outputs must be new files under existing parents. Source/review files are
limited to 50 MB, policies to 1 MB. Retaining both source and derived report can
make an export too large; it is refused, not truncated. Unexpected I/O failure
may leave a partial new file for inspection.

## Interpretation boundary

A relaxed requirement can make a verdict pass without improving any outcome.
Changing `fail_on` changes enforcement, not measured adequacy. The summary
separates original and proposed requirements/enforcement and records zero model
calls. Do not replace original evidence or call this a new benchmark run.

Choosing thresholds after seeing results does not validate the policy or
restore statistical guarantees. Security Wilson summaries retain their
dependence, selection, and fixed-benchmark limitations; this command adds no
post-selection inference. Use a separately reviewed protocol and new authorized
evidence when prospective testing is required.

Digests establish identity when retained independently, not execution
authenticity, trusted time, observation truth, approval, or certification.
Identifiers/outcomes remain in the artifact: review before sharing. The
[schema](../dspy_security_bench/schemas/scan-policy-review.schema.json) references
the sibling scan-evidence schema; structural checks do not replace native replay.
