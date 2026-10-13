"""Compare collection requirements against pinned bytes, without reviewing evidence."""

from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from dspy_security_bench.jsonio import read_json_snapshot
from dspy_security_bench.proofrun_collection import (
    MAX_PLAN_BYTES,
    POLICY_FIELDS,
    _digest,
    validate_plan,
)

REASONS = {
    "unchanged": "Plan bytes are unchanged; this does not verify evidence or approve deployment.",
    "format_only": "Plan values are unchanged but exact bytes differ; retain a newly approved pin before use.",
    "requirements_changed": "Required entries, order, artifact pins, or policies changed; owner review is required.",
    "invalid_policy": "A lowercase SHA-256 baseline pin from an independent trusted channel is required.",
    "invalid_baseline": "Baseline must be a readable, bounded, valid collection plan; source details withheld.",
    "baseline_pin_mismatch": "Baseline bytes do not match the independent pin; candidate was not read.",
    "invalid_candidate": "Candidate must be a readable, bounded, valid collection plan; source details withheld.",
}


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _project(entry, index, policy):
    return {
        "index": index, "path_sha256": _hash(entry["path"]),
        "bundle_type": entry["bundle_type"], "file_sha256": entry["file_sha256"],
        "policy": policy.public_fields(),
    }


def compare_plans(baseline: Path, candidate: Path, *, expected_baseline_file_sha256: str) -> dict:
    """Read at most two 1 MB plans; never read their artifacts or invoke a verifier.

    Exit 0 requires identical valid bytes, 1 requires owner review of changed
    bytes, and 2 means comparison could not be established. The pin must be
    independently owner-approved; a supplied plan/hash pair is not authentication.
    """
    try:
        package_version = version("dspy-security-bench")
    except PackageNotFoundError:
        package_version = "unknown"
    result = {
        "schema_version": 1, "review_type": "ProofRun collection plan comparison", "verifier_version": package_version,
        "expected_baseline_file_sha256": None, "baseline_file_sha256": None, "candidate_file_sha256": None,
        "entries": [], "summary": {"added": 0, "removed": 0, "modified": 0, "unchanged": 0},
        "comparison_is_approval": False, "artifact_evidence_verified": False, "requirements_completeness_established": False,
    }

    def finish(code, reason):
        return {**result, "exit_code": code, "verdict": ("unchanged", "review_required", "invalid")[code], "reason_code": reason}

    if not _digest(expected_baseline_file_sha256):
        return finish(2, "invalid_policy")
    result["expected_baseline_file_sha256"] = expected_baseline_file_sha256
    try:
        before_raw, before = read_json_snapshot(Path(baseline), MAX_PLAN_BYTES)
        result["baseline_file_sha256"] = hashlib.sha256(before_raw).hexdigest()
        if result["baseline_file_sha256"] != expected_baseline_file_sha256:
            return finish(2, "baseline_pin_mismatch")
        before_policies = validate_plan(before)
    except (OSError, ValueError, TypeError):
        return finish(2, "invalid_baseline")
    try:
        after_raw, after = read_json_snapshot(Path(candidate), MAX_PLAN_BYTES)
        result["candidate_file_sha256"] = hashlib.sha256(after_raw).hexdigest()
        after_policies = validate_plan(after)
    except (OSError, ValueError, TypeError):
        return finish(2, "invalid_candidate")

    old = {entry["id"]: (i, entry, before_policies[i]) for i, entry in enumerate(before["entries"])}
    new = {entry["id"]: (i, entry, after_policies[i]) for i, entry in enumerate(after["entries"])}
    # Baseline order first, then newly added IDs in candidate order. Never sort
    # attacker-supplied labels into diagnostics or infer an entry rename.
    for identity in dict.fromkeys([*old, *new]):
        left, right = old.get(identity), new.get(identity)
        fields = []
        if left is not None and right is not None:
            if left[0] != right[0]:
                fields.append("position")
            fields.extend(field for field in ("path", "bundle_type", "file_sha256") if left[1][field] != right[1][field])
            fields.extend("policy." + field for field in sorted(POLICY_FIELDS)
                          if left[1]["policy"][field] != right[1]["policy"][field])
        status = "added" if left is None else "removed" if right is None else "modified" if fields else "unchanged"
        result["entries"].append({
            "entry_id_sha256": _hash(identity), "status": status, "changed_fields": fields,
            "before": _project(left[1], left[0], left[2]) if left is not None else None,
            "after": _project(right[1], right[0], right[2]) if right is not None else None,
        })
        result["summary"][status] += 1
    if before_raw == after_raw:
        return finish(0, "unchanged")
    return finish(1, "format_only" if before == after else "requirements_changed")


def render_plan_comparison(result: dict) -> str:
    lines = [f"Collection plan comparison: {result['verdict']}", REASONS[result["reason_code"]]]
    for row in result["entries"]:
        before = "absent" if row["before"] is None else str(row["before"]["index"] + 1)
        after = "absent" if row["after"] is None else str(row["after"]["index"] + 1)
        fields = ", ".join(row["changed_fields"]) or "no shared-entry field changes"
        lines.append(f"Entry {before} -> {after}: {row['status']}; {fields}")
    lines.append("Plans only: no artifact evidence verified, completeness established, or change approved.")
    return "\n".join(lines)
