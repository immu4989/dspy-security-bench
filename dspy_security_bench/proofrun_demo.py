"""Model-free owner-to-recipient walkthrough with deliberate adverse outcomes."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

from dspy_security_bench.jsonio import read_json_snapshot
from dspy_security_bench.outputio import check_directory, check_new_directory, write_new_file
from dspy_security_bench.proofrun_plan_diff import compare_plans
from dspy_security_bench.proofrun_prepare import REQUIREMENTS_TYPE, encode_plan, prepare_plan_file
from dspy_security_bench.proofrun_reports import export_collection_reports
from dspy_security_bench.proofrun_snapshot import PLAN_FILENAME, snapshot_collection

DISCLAIMER = (
    "Synthetic teaching fixtures only: no external model, production system, supplier, or government agency was evaluated. "
    "This is not certification, deployment approval, a sharing approval, or proof of complete requirements."
)


def _fixtures() -> dict[str, dict]:
    from dspy_security_bench.causal.proof import build_demo_inputs
    from dspy_security_bench.causal.registry import build_causal_submission_bundle
    from dspy_security_bench.collective.registry import build_collective_submission_bundle
    from dspy_security_bench.collective.v2 import built_in_scenario_v2
    from dspy_security_bench.defend.evidence import build_evidence_bundle
    from dspy_security_bench.defend.protocol import (
        analyze_remediation,
        built_in_mission,
        built_in_proposal,
    )

    metadata = {
        "submitter": "synthetic-collection-demo-not-a-supplier", "runtime": "synthetic-no-live-system",
        "source_repository": "https://example.com/synthetic-collection-demo",
        "created_at": "2026-01-01",  # Fixture date, not observed execution time.
        "known_gaps": ["Teaching fixture only; no external model or production system was evaluated."],
    }
    mission = built_in_mission("community-hospital")
    return {
        "collective.json": build_collective_submission_bundle(
            built_in_scenario_v2("hardened-complete"), deployment_class="fictional-training-only", **metadata),
        "causal.json": build_causal_submission_bundle(*build_demo_inputs(), **metadata),
        "defense.json": build_evidence_bundle(
            analyze_remediation(mission, built_in_proposal(mission)), deployment_class="fictional-training-only", **metadata),
    }


def _readme(base_pin: str, provenance_pin: str) -> str:
    return f"""# Synthetic collection handoff: owner, supplier, reviewer

{DISCLAIMER}

No API keys, network calls, live adapters, or operational data are needed.
Every artifact uses a fixed illustrative date, not a trusted execution time.
The three bundled structural fixtures cover declared containment, causality,
and remediation. Their presence is not proof that an organization's requirements
are complete. Do not submit these files as independent or measured community results.

## Start with the outcomes

Open `reports/review.html`, `provenance-reports/review.html`, and
`missing-reports/review.html` locally. Each folder also contains JSON, JUnit, and
an unsigned byte manifest, all rendered from one native review. `demo.json`
records the actual observed outcomes, not just expected tutorial answers.

| Case | Native exit | What to notice |
| --- | --- | --- |
| Complete local evidence | 0 | All three slots pass selected offline checks; provenance is not checked |
| Provenance required | 1 | The structural bundle cannot establish authenticated execution; it is not promoted by choosing online mode |
| Required evidence missing | 2 | The defense slot remains a required error; the other two slots are still reviewed |

Exit 0 is not a finding that a system is secure. Native reports can contain
adverse structural findings while remaining valid evidence. Open original JSON
artifacts to understand those findings and limitations.

## Replay from this directory

Run these commands one at a time. Nonzero exits in the adverse cases are expected;
do not suppress them in real CI. The literal pins below identify this generated
fixture only. In a real handoff, obtain the approved plan pin through an
independent trusted channel; this README and the files do not authenticate each other.

```sh
# 1. Owner-authored requirements become a draft, not an approved plan. Exit 0.
dspy-security-bench proofrun prepare-plan owner/requirements.json --out owner/replayed-plan.json --json

# 2. Copy the exact required bytes to a new local handoff directory. Exit 0.
dspy-security-bench proofrun snapshot-collection owner/collection-plan.json --expected-plan-file-sha256 {base_pin} --out replay-handoff --json

# 3. Recipient reruns native review once and gets all report formats. Exit 0.
dspy-security-bench proofrun verify-collection replay-handoff/collection-plan.json --expected-plan-file-sha256 {base_pin} --report-dir replay-reports

# 4. A hypothetical policy change must be visible. Exit 1: owner review required.
dspy-security-bench proofrun compare-plans owner/collection-plan.json provenance-required/collection-plan.json --expected-baseline-file-sha256 {base_pin} --json

# 5. Structural evidence does not satisfy requested authenticated provenance. Exit 1.
dspy-security-bench proofrun verify-collection provenance-required/collection-plan.json --expected-plan-file-sha256 {provenance_pin} --json

# 6. Missing evidence is not removed from the pinned requirements. Exit 2.
dspy-security-bench proofrun verify-collection missing/collection-plan.json --expected-plan-file-sha256 {base_pin} --json
```

The initial `recipient/` snapshot is already independent of `owner/`; a recipient
does not need the sender's original directory. The missing case deliberately
omits a file while keeping the original plan. `policy-comparison.json` records
the online-policy change against the pinned baseline; it is not an approval.
The generated report sets contain source-redacted decisions, but `owner/`,
`recipient/`, and the two adverse-case folders contain full original fixture
content. Real snapshots require an authorized sharing review before transfer.

## Use your own evidence responsibly

Author explicit requirements and policies for an authorized synthetic test of
your own system. Replace fixture artifacts, prepare a new draft, review changes,
retain approved pins independently, and have the recipient rerun native review.
Do not relabel this demo as a deployment evaluation, weaken requirements to
obtain green output, or omit unfavorable findings. No automated acceptance,
procurement action, production change, upload, or certification occurs here.

Output destinations must be new and have stable owner-controlled parents.
If interrupted, inspect any partial directory and use a fresh destination.
Replaying creation commands twice will refuse to overwrite the first outputs.
Fixture bytes are deterministic; JUnit scope hashes can differ when the same
files are reviewed under different local paths.
"""


def _expected_review(name: str, review: dict) -> bool:
    missing, unmet = name == "missing-evidence", name == "provenance-required"
    expected = {"required": 3, "reviewed": 2 if missing else 3,
                "passed": 2 if missing or unmet else 3, "not_passed": int(unmet), "invalid": int(missing)}
    if review.get("summary") != expected or review.get("reason_code") != "completed":
        return False
    rows = review.get("entries", [])
    if len(rows) != 3:
        return False
    for index, row in enumerate(rows):
        if missing and index == 2:
            if row.get("status") != "invalid_input" or row.get("review") is not None:
                return False
        else:
            native = row.get("review") or {}
            online = unmet and index == 0
            if (row.get("status") != "reviewed" or native.get("integrity") != "valid"
                    or native.get("eligibility") != "eligible"
                    or native.get("provenance") != ("unverified" if online else "not_checked")
                    or native.get("reason_code") != ("attestation_unverified" if online else "offline_verified")):
                return False
    return True


def create_collection_demo(output: Path) -> dict:
    """Generate and check three teaching cases using the real handoff workflow.

    Only bundled data-only fixtures are used. Existing output is never replaced;
    an unexpected failure can leave partial new output for inspection.
    """
    receipt = {"schema_version": 1, "demo_type": "Synthetic ProofRun collection walkthrough",
               "demo_complete": False, "synthetic": True, "claim_boundary": DISCLAIMER, "cases": []}

    def fail(reason):
        return {**receipt, "exit_code": 2, "reason_code": reason}

    try:
        output = check_new_directory(Path(output))
    except (OSError, TypeError, ValueError):
        return fail("invalid_output")
    try:
        bundles = _fixtures()
        raw_artifacts = {name: encode_plan(bundle) for name, bundle in bundles.items()}
        requirements = {
            "schema_version": 1, "requirements_type": REQUIREMENTS_TYPE,
            "entries": [{"id": name.removesuffix(".json"), "path": name, "bundle_type": bundle["bundle_type"],
                         "policy": {"minimum_trials": None, "offline": True, "attestation_repository": None,
                                    "require_trusted_builder": False, "allow_self_hosted_runner": False}}
                        for name, bundle in bundles.items()],
        }
    except Exception:
        return fail("fixture_error")
    try:
        check_new_directory(output)
        output.mkdir(mode=0o700)
        check_directory(output)
        owner = output / "owner"
        owner.mkdir(mode=0o700)
        for name, raw in raw_artifacts.items():
            write_new_file(owner / name, raw)
        write_new_file(owner / "requirements.json", encode_plan(requirements))
        prepared = prepare_plan_file(owner / "requirements.json", owner / PLAN_FILENAME)
        if prepared["exit_code"] != 0:
            return fail("preparation_error")
        write_new_file(output / "preparation-receipt.json", encode_plan(prepared))
        base_pin = prepared["plan_file_sha256"]
        copied = snapshot_collection(owner / PLAN_FILENAME, output / "recipient", expected_plan_file_sha256=base_pin)
        if copied["exit_code"] != 0:
            return fail("snapshot_error")
        write_new_file(output / "snapshot-receipt.json", encode_plan(copied))
        plan_raw = (owner / PLAN_FILENAME).read_bytes()
        changed = deepcopy(json.loads(plan_raw))
        changed["entries"][0]["policy"]["offline"] = False
        changed_raw = encode_plan(changed)
        changed_pin = hashlib.sha256(changed_raw).hexdigest()
        for name, plan_bytes, omit in (("provenance-required", changed_raw, None), ("missing", plan_raw, "defense.json")):
            destination = output / name
            destination.mkdir(mode=0o700)
            for filename, raw in raw_artifacts.items():
                if filename != omit:
                    write_new_file(destination / filename, raw)
            write_new_file(destination / PLAN_FILENAME, plan_bytes)
        comparison = compare_plans(owner / PLAN_FILENAME, output / "provenance-required" / PLAN_FILENAME,
                                   expected_baseline_file_sha256=base_pin)
        if comparison["exit_code"] != 1 or comparison["summary"]["modified"] != 1:
            return fail("unexpected_demo_outcome")
        write_new_file(output / "policy-comparison.json", encode_plan(comparison))
        for name, folder, reports, pin, expected in (
            ("complete", "recipient", "reports", base_pin, 0),
            ("provenance-required", "provenance-required", "provenance-reports", changed_pin, 1),
            ("missing-evidence", "missing", "missing-reports", base_pin, 2),
        ):
            exported = export_collection_reports(output / folder / PLAN_FILENAME, output / reports,
                                                  expected_plan_file_sha256=pin)
            receipt["cases"].append({"name": name, "plan": f"{folder}/{PLAN_FILENAME}", "reports": reports,
                                     "plan_file_sha256": pin, "expected_exit_code": expected,
                                     "observed_exit_code": exported["native_exit_code"]})
            if not exported["report_set_complete"] or exported["exit_code"] != expected:
                return fail("unexpected_demo_outcome")
            raw, reviewed = read_json_snapshot(output / reports / "review.json", 1_000_000)
            if (hashlib.sha256(raw).hexdigest() != exported["review_file_sha256"]
                    or not _expected_review(name, reviewed)):
                return fail("unexpected_demo_outcome")
        write_new_file(output / "README.md", _readme(base_pin, changed_pin).encode("utf-8"))
        completed = {**receipt, "demo_complete": True, "exit_code": 0, "reason_code": "created"}
        write_new_file(output / "demo.json", encode_plan(completed))
        return completed
    except Exception:
        # The demo uses no user-supplied artifacts or code; unexpected fixture or
        # storage errors still withhold raw diagnostics and never report success.
        return fail("demo_error")
