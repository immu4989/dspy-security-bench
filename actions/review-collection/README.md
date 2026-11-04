# Owner-pinned collection review in GitHub Actions

This **unreleased, Linux-only** action reviews original evidence; it does not run
supplier code or accept a saved report as evidence. Use a full reviewed commit
SHA containing this directory. It is separate from the repository-root action,
which executes experiments and can upload/attest their results.

The action requires an independently retained owner-approved plan SHA-256,
preserves every entry's native policy, and evaluates the collection once. A new
private directory under `RUNNER_TEMP` contains synchronized JSON, HTML, JUnit,
and an unsigned byte manifest. It does not upload files, attest execution,
post comments, edit summaries, or install the caller's project. No model keys
or write permissions are needed. Online policies can invoke `gh` attestation
verification and need deployment-owned access and network configuration.

Runtime setup uses a pinned uv installer and this action revision's `uv.lock`.
It creates a fresh environment under `RUNNER_TEMP`, synchronizes with `--locked`,
and installs the reviewer non-editably without development/default groups.
Missing or stale lockfiles fail setup rather than being regenerated. Caller
virtual environments are not synchronized, caller project configuration is not
discovered, and review does not fall back to a preinstalled package. A successful
setup exposes the exact lockfile hash for workflow records. Setup can use the
network for the interpreter, locked distributions, and source build requirements.
Inherited uv configuration/selection/synchronization overrides are discarded;
only `UV_CACHE_DIR`, `UV_PYTHON_INSTALL_DIR`, `UV_OFFLINE`, and
`UV_PYTHON_DOWNLOADS` survive as runner controls. Custom package-index overrides
are not an action interface; provision a deployment-owned runtime and use the
CLI directly if your environment requires a different supply path.

## Consumer workflow

Use an owner-controlled workflow, trusted runner, reviewed dependency supply,
and stable local evidence paths. Stage authorized evidence as data only; do not
execute an untrusted checkout, install its dependencies, or use
`pull_request_target` to run supplier-controlled code. Configure
`OWNER_COLLECTION_PLAN_SHA256` as an owner-managed variable outside the supplier's
change. A hash computed from the submitted plan in this job is not an independent
requirement pin. `FULL_REVIEWED_COMMIT_SHA` below is a deliberate placeholder:
replace it with the reviewed 40-character action revision before use.

```yaml
permissions:
  contents: read
jobs:
  evidence-review:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      # Here intake/ is an authorized data-only handoff already in this checkout.
      - name: Review all owner-required evidence
        id: review
        uses: immu4989/dspy-security-bench/actions/review-collection@FULL_REVIEWED_COMMIT_SHA
        with:
          plan: intake/collection-plan.json
          expected-plan-file-sha256: ${{ vars.OWNER_COLLECTION_PLAN_SHA256 }}
      # OPTIONAL: omit this step unless organizational sharing policy permits it.
      - name: Retain completed reports, including failed reviews
        if: ${{ !cancelled() && steps.review.outputs.report-set-complete == 'true' }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: evidence-review-${{ github.run_id }}-${{ github.run_attempt }}
          path: |
            ${{ steps.review.outputs.report-directory }}/review.json
            ${{ steps.review.outputs.report-directory }}/review.html
            ${{ steps.review.outputs.report-directory }}/review.xml
            ${{ steps.review.outputs.report-directory }}/manifest.json
          if-no-files-found: error
          retention-days: 7
          include-hidden-files: false
```

Do not add consumer-level `continue-on-error` or `|| true`: the action fails on
native exit 1 or 2. Internally it retains outputs before a final mandatory gate.
Setup failures, missing outputs, incomplete exports, and unexpected gate state
fail closed. An export can be complete even when evidence is invalid: inspect
`exit-code`, not merely `report-set-complete`. Source evidence never belongs in
the report upload path. Hashes remain linkable; source-redacted does not mean
anonymous or authorized to share. Uploads are optional and independently fail
the job if unsuccessful; they do not override the evidence-review result.

| Output | Meaning |
| --- | --- |
| `exit-code` | Native 0/1/2 when export completed; 2 on adapter/export failure; may be absent if setup failed |
| `report-set-complete` | `true` for all four reports from one decision; not a pass or approval |
| `report-directory` | New runner-temporary directory, exposed only for complete exports |
| `manifest-file-sha256` | Exact unsigned manifest bytes; not authenticated execution |
| `dependency-lock-sha256` | Action lockfile used by successful setup; not a signature or proof that every runner component is pinned |

Inputs are passed as environment data rather than interpolated into shell
source, and Python runs in isolated mode to avoid import shadowing by the intake
checkout. Runtime dependency resolution is constrained by the reviewed lockfile;
this is not a hermetic or fully reproducible build. Python's patch version, the
runner image, GitHub CLI, trusted package caches, and isolated
build-backend requirements remain deployment dependencies. A lockfile hash is
not an authenticity claim. Source/lockfile changes observed during setup fail
closed, but the runner must still prevent concurrent modification by other
processes. This does not authenticate the initial requirement pin or establish
that a deployment is safe. For air-gapped, fully provisioned, or non-Linux
deployments, provision the reviewed package yourself and use
`proofrun verify-collection --report-dir` directly. Partial setup environments
are retained under runner temporary storage for diagnosis, never reused by a
subsequent invocation, and follow the runner's own cleanup policy.

Tests execute the real review and final-gate shell with all three native
outcomes, import-shadowing attempts, invalid pins, partial exports, and missing
outputs. The repository's separate smoke workflow exercises the composite action
on GitHub; a local test does not establish a hosted run passed. Its deliberate
failed-case assertions are test-only, not a recommended consumer bypass.

See [native report contracts](../../docs/proofrun.md#export-all-report-formats-from-one-review-on-main),
[GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use),
and [artifact upload behavior and platform limitations](https://github.com/actions/upload-artifact).
The runtime follows uv's documented [locked synchronization](https://docs.astral.sh/uv/concepts/projects/sync/)
and [dedicated project environment](https://docs.astral.sh/uv/concepts/projects/config/) semantics.
