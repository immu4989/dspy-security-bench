"""Owner-planned, source-redacted review of a required evidence collection.

All entries are required; no discovery, downloads, code loading, or publication.
A plan's completeness and provenance remain the owner's responsibility.
"""

from __future__ import annotations

import hashlib
import re
import stat
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from dspy_security_bench.jsonio import decode_json_object
from dspy_security_bench.jsonio import read_regular_bytes as _read_regular
from dspy_security_bench.proofrun_review import (
    ALL_FAMILIES,
    MAX_BUNDLE_BYTES,
    STRUCTURAL_FAMILIES,
    ReviewPolicy,
    review_bundle_bytes,
)

MAX_PLAN_BYTES = 1_000_000
MAX_ENTRIES = 25
MAX_TOTAL_BYTES = 100_000_000
PLAN_TYPE = "ProofRun review collection plan"
POLICY_FIELDS = {"minimum_trials", "offline", "attestation_repository", "require_trusted_builder", "allow_self_hosted_runner"}
ENTRY_FIELDS = {"id", "path", "bundle_type", "file_sha256", "policy"}
REASONS = {
    "completed": "Every planned entry has a recorded outcome; inspect individual decisions.",
    "invalid_policy": "Expected plan pin must be lowercase SHA-256; source details withheld.",
    "invalid_plan": "Plan must be bounded strict JSON with valid distinct required entries and policies; source details withheld.",
    "plan_pin_mismatch": "Plan bytes do not match the independent pin.",
}


def _digest(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _portable_path(value) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 240 or not value.endswith(".json"):
        return False
    for part in value.split("/"):
        if (re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", part) is None
                or part.endswith(".") or part.split(".")[0].upper() in {
                    "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10)),
                }):
            return False
    return True


def validate_plan(plan: dict) -> list[ReviewPolicy]:
    """Validate the entire plan before reading any referenced file or using gh."""
    if (not isinstance(plan, dict) or set(plan) != {"schema_version", "plan_type", "entries"}
            or type(plan["schema_version"]) is not int or plan["schema_version"] != 1 or plan["plan_type"] != PLAN_TYPE):
        raise ValueError("invalid plan envelope")
    entries = plan["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValueError("invalid entry count")
    ids, paths, pins, policies = set(), set(), set(), []
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS
                or not isinstance(entry["id"], str) or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", entry["id"]) is None
                or len(entry["id"]) > 64 or not _portable_path(entry["path"]) or not _digest(entry["file_sha256"])
                or not isinstance(entry["bundle_type"], str) or entry["bundle_type"] not in ALL_FAMILIES
                or not isinstance(entry["policy"], dict) or set(entry["policy"]) != POLICY_FIELDS):
            raise ValueError("invalid entry shape")
        if entry["id"] in ids or entry["path"].casefold() in paths or entry["file_sha256"] in pins:
            raise ValueError("duplicate entry, path, or artifact pin")
        ids.add(entry["id"])
        paths.add(entry["path"].casefold())
        pins.add(entry["file_sha256"])
        policy = ReviewPolicy(**entry["policy"], expected_file_sha256=entry["file_sha256"])
        policy.public_fields()
        if (entry["bundle_type"] in STRUCTURAL_FAMILIES) != (policy.minimum_trials is None):
            raise ValueError("policy does not apply to expected bundle family")
        policies.append(policy)
    return policies


def _entry_path(root: Path, relative: str) -> Path:
    current = root
    for part in relative.split("/"):
        current = current / part
        # On Windows, junctions are reparse points rather than symlinks.
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("linked paths are unsupported")
    return current


def review_collection(path: Path, *, expected_plan_file_sha256: str | None = None) -> dict:
    """Review every required entry; aggregate exit is max(0 pass, 1 unmet, 2 invalid).

    A malformed plan rejects the whole request before referenced-file intake.
    An invalid individual file never hides subsequent entries. No per-entry
    failure can be outvoted by successful entries.
    """
    try:
        package_version = version("dspy-security-bench")
    except PackageNotFoundError:
        package_version = "unknown"
    result = {
        "schema_version": 1, "review_type": "ProofRun collection verification", "verifier_version": package_version,
        "plan_file_sha256": None, "expected_plan_file_sha256": None,
        "entries": [], "summary": {"required": 0, "reviewed": 0, "passed": 0, "not_passed": 0, "invalid": 0},
        "review_is_attestation": False, "execution_reproduced": False, "requirements_completeness_established": False,
    }

    def finish(code, reason):
        return {**result, "exit_code": code, "verdict": ("pass", "not_passed", "invalid")[code], "reason_code": reason}

    if expected_plan_file_sha256 is not None and not _digest(expected_plan_file_sha256):
        return finish(2, "invalid_policy")
    result["expected_plan_file_sha256"] = expected_plan_file_sha256
    try:
        path = Path(path)
        raw = _read_regular(path, MAX_PLAN_BYTES)
        if len(raw) > MAX_PLAN_BYTES:
            raise ValueError("plan byte budget exceeded")
        result["plan_file_sha256"] = hashlib.sha256(raw).hexdigest()
        if expected_plan_file_sha256 is not None and result["plan_file_sha256"] != expected_plan_file_sha256:
            return finish(2, "plan_pin_mismatch")
        plan = decode_json_object(raw, MAX_PLAN_BYTES)
        policies = validate_plan(plan)
        root = path.resolve().parent
    except (OSError, ValueError, TypeError):
        return finish(2, "invalid_plan")
    remaining, exit_code = MAX_TOTAL_BYTES, 0
    for index, (entry, policy) in enumerate(zip(plan["entries"], policies, strict=True)):
        row = {
            "index": index, "entry_id_sha256": hashlib.sha256(entry["id"].encode()).hexdigest(),
            "expected_bundle_type": entry["bundle_type"], "expected_file_sha256": entry["file_sha256"],
            "input_file_sha256": None, "status": "invalid_input", "review": None,
        }
        result["entries"].append(row)
        code = 2
        if remaining <= 0:
            row["status"] = "byte_budget_exceeded"
        else:
            limit = min(MAX_BUNDLE_BYTES, remaining)
            snapshot, read_attempted = None, False
            try:
                source = _entry_path(root, entry["path"])
                if not stat.S_ISREG(source.lstat().st_mode):
                    raise ValueError("entry is not a regular file")
                read_attempted = True
                snapshot = _read_regular(source, limit)
                remaining -= len(snapshot)
                if len(snapshot) > limit:
                    row["status"] = "byte_budget_exceeded"
                else:
                    row["input_file_sha256"] = hashlib.sha256(snapshot).hexdigest()
                    # Pin/type checks and review all consume these exact bytes.
                    if row["input_file_sha256"] != entry["file_sha256"]:
                        row["status"] = "pin_mismatch"
                    elif decode_json_object(snapshot, limit).get("bundle_type") != entry["bundle_type"]:
                        row["status"] = "bundle_type_mismatch"
                    else:
                        row["review"] = review_bundle_bytes(snapshot, policy=policy)
                        row["status"] = "reviewed"
                        code = row["review"]["exit_code"]
            except (OSError, ValueError, TypeError):
                # Bound aggregate work conservatively if a read fails partway.
                # Successful reads above are already charged exactly once.
                if read_attempted and snapshot is None:
                    remaining -= limit + 1
        summary = result["summary"]
        summary["required"] += 1
        summary["reviewed"] += row["review"] is not None
        summary[("passed", "not_passed", "invalid")[code]] += 1
        exit_code = max(exit_code, code)
    return finish(exit_code, "completed")


def render_collection(result: dict) -> str:
    lines = [f"Collection review: {result['verdict']}", REASONS[result["reason_code"]]]
    for row in result["entries"]:
        reason = row["review"]["reason_code"] if row["review"] else row["status"]
        lines.append(f"Entry {row['index'] + 1}: {reason}")
    counts = result["summary"]
    lines.append(f"Required: {counts['required']}; passed: {counts['passed']}; not passed: {counts['not_passed']}; invalid: {counts['invalid']}")
    lines.append("This unsigned review does not prove requirement completeness, independent execution, or deployment approval.")
    return "\n".join(lines)
