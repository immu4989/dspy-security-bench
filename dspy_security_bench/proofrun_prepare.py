"""Prepare, but never approve, a collection plan from explicit owner requirements."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

from dspy_security_bench.jsonio import decode_json_object, read_json_snapshot, read_regular_bytes
from dspy_security_bench.proofrun_collection import (
    ENTRY_FIELDS,
    MAX_BUNDLE_BYTES,
    MAX_ENTRIES,
    MAX_PLAN_BYTES,
    MAX_TOTAL_BYTES,
    PLAN_TYPE,
    _digest,
    _entry_path,
    _portable_path,
    validate_plan,
)

REQUIREMENTS_TYPE = "ProofRun collection requirements"
REASONS = {
    "prepared": "Draft plan prepared from observed bytes; owner approval and native evidence review are still required.",
    "invalid_policy": "Expected requirements pin must be lowercase SHA-256; source details withheld.",
    "invalid_requirements": "Requirements must be bounded strict JSON with explicit valid slots and policies; source details withheld.",
    "requirements_pin_mismatch": "Requirements do not match the independent pin; no artifacts were read.",
    "invalid_artifact": "Required artifact could not be read as bounded strict JSON; source details withheld.",
    "bundle_type_mismatch": "Artifact type does not match its owner-selected required family.",
    "byte_budget_exceeded": "Artifact intake exceeds the per-file or aggregate byte budget.",
    "duplicate_artifact": "Identical artifact bytes cannot fill multiple required slots.",
    "invalid_output": "Output must be a new ordinary file beside the requirements in an existing unlinked directory.",
    "output_error": "Draft could not be written; inspect the destination for a partial new file. Existing files are never overwritten.",
}


def encode_plan(plan: dict) -> bytes:
    return (json.dumps(plan, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def validate_requirements(requirements: dict) -> dict:
    """Reuse the full plan contract with distinct internal placeholder hashes.

    Placeholders are never returned by preparation or written as artifact pins.
    No policy, slot, expected type, or path is inferred from artifact contents.
    """
    if (not isinstance(requirements, dict) or set(requirements) != {"schema_version", "requirements_type", "entries"}
            or type(requirements["schema_version"]) is not int or requirements["schema_version"] != 1
            or requirements["requirements_type"] != REQUIREMENTS_TYPE
            or not isinstance(requirements["entries"], list) or not 1 <= len(requirements["entries"]) <= MAX_ENTRIES):
        raise ValueError("invalid requirements envelope")
    entries = []
    for index, entry in enumerate(requirements["entries"]):
        if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS - {"file_sha256"}:
            raise ValueError("invalid required entry")
        entries.append({**entry, "file_sha256": hashlib.sha256(f"placeholder-{index}".encode()).hexdigest()})
    plan = {"schema_version": 1, "plan_type": PLAN_TYPE, "entries": entries}
    validate_plan(plan)
    # Replacement hashes have exactly the same length. Admit the final encoded
    # plan size before reading artifacts, including JSON escaping/indentation.
    if len(encode_plan(plan)) > MAX_PLAN_BYTES:
        raise ValueError("prepared plan would exceed the plan byte budget")
    return plan


def _receipt() -> dict:
    return {
        "schema_version": 1, "review_type": "ProofRun collection plan preparation",
        "expected_requirements_file_sha256": None, "requirements_file_sha256": None, "plan_file_sha256": None,
        "required_entries": 0, "observed_entries": 0, "failed_entry_index": None,
        "plan_is_approved": False, "artifact_evidence_verified": False, "requirements_completeness_established": False,
    }


def prepare_plan(path: Path, *, expected_requirements_file_sha256: str | None = None) -> tuple[dict | None, dict]:
    """Return a full-content draft and a source-redacted receipt, with no writes.

    The receipt is not a verification result. Referenced artifacts are checked
    for strict JSON and declared family only; native meaning/authenticity are
    deliberately left to verify-collection after accountable owner approval.
    """
    receipt = _receipt()

    def fail(reason, index=None):
        return None, {**receipt, "exit_code": 2, "reason_code": reason, "failed_entry_index": index}

    if expected_requirements_file_sha256 is not None and not _digest(expected_requirements_file_sha256):
        return fail("invalid_policy")
    receipt["expected_requirements_file_sha256"] = expected_requirements_file_sha256
    try:
        path = Path(path)
        raw, requirements = read_json_snapshot(path, MAX_PLAN_BYTES)
        receipt["requirements_file_sha256"] = hashlib.sha256(raw).hexdigest()
        if expected_requirements_file_sha256 is not None and receipt["requirements_file_sha256"] != expected_requirements_file_sha256:
            return fail("requirements_pin_mismatch")
        plan = validate_requirements(requirements)
        root = path.resolve().parent
    except (OSError, TypeError, ValueError):
        return fail("invalid_requirements")
    receipt["required_entries"] = len(plan["entries"])
    remaining, pins = MAX_TOTAL_BYTES, set()
    for index, entry in enumerate(plan["entries"]):
        if remaining <= 0:
            return fail("byte_budget_exceeded", index)
        limit = min(MAX_BUNDLE_BYTES, remaining)
        try:
            raw = read_regular_bytes(_entry_path(root, entry["path"]), limit)
            remaining -= len(raw)
            if len(raw) > limit:
                return fail("byte_budget_exceeded", index)
            artifact = decode_json_object(raw, limit)
        except (OSError, TypeError, ValueError):
            return fail("invalid_artifact", index)
        if artifact.get("bundle_type") != entry["bundle_type"]:
            return fail("bundle_type_mismatch", index)
        pin = hashlib.sha256(raw).hexdigest()
        if pin in pins:
            return fail("duplicate_artifact", index)
        pins.add(pin)
        entry["file_sha256"] = pin
        receipt["observed_entries"] += 1
    # The same native plan contract must admit the exact completed draft.
    validate_plan(plan)
    receipt["plan_file_sha256"] = hashlib.sha256(encode_plan(plan)).hexdigest()
    return plan, {**receipt, "exit_code": 0, "reason_code": "prepared"}


def _destination(source: Path, output: Path) -> Path:
    output = output.absolute()
    if not _portable_path(output.name) or output.parent.resolve() != source.resolve().parent:
        raise ValueError("draft must remain beside the requirements")
    # Exclusive creation rejects even dangling links and existing hard links.
    # Parent observations additionally reject Windows junction/reparse paths.
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("output already exists")
    for parent in output.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            raise ValueError("output parent must be an unlinked directory")
    return output


def prepare_plan_file(path: Path, output: Path, *, expected_requirements_file_sha256: str | None = None) -> dict:
    """Exclusively create a new draft beside its inputs; never overwrite a plan.

    Input snapshots bind observed bytes, not files that may change afterwards.
    Stable owner-controlled directories are required, not an adversarial-path
    sandbox. An I/O failure can leave a partial new output for owner inspection.
    """
    if expected_requirements_file_sha256 is not None and not _digest(expected_requirements_file_sha256):
        return {**_receipt(), "exit_code": 2, "reason_code": "invalid_policy"}
    try:
        path, output = Path(path), Path(output)
        destination = _destination(path, output)
    except (OSError, ValueError, TypeError):
        return {**_receipt(), "exit_code": 2, "reason_code": "invalid_output"}
    plan, receipt = prepare_plan(path, expected_requirements_file_sha256=expected_requirements_file_sha256)
    if plan is None:
        return receipt
    try:
        _destination(path, output)
        with destination.open("xb") as stream:
            stream.write(encode_plan(plan))
    except (OSError, ValueError):
        return {**receipt, "plan_file_sha256": None, "exit_code": 2, "reason_code": "output_error"}
    return receipt


def render_preparation(receipt: dict) -> str:
    lines = [REASONS[receipt["reason_code"]]]
    if receipt["failed_entry_index"] is not None:
        lines.append(f"Failed required entry: {receipt['failed_entry_index'] + 1}")
    if receipt["plan_file_sha256"] is not None:
        lines.append(f"Draft plan file sha256: {receipt['plan_file_sha256']}")
    lines.append("The draft contains owner-selected labels, paths, and repository constraints; review before sharing.")
    return "\n".join(lines)
