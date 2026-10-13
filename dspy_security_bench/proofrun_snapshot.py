"""Exact-byte collection handoff, without evidence approval or archive extraction."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from dspy_security_bench.jsonio import decode_json_object, read_regular_bytes
from dspy_security_bench.proofrun_collection import (
    MAX_BUNDLE_BYTES,
    MAX_PLAN_BYTES,
    MAX_TOTAL_BYTES,
    _digest,
    _entry_path,
    validate_plan,
)

PLAN_FILENAME = "collection-plan.json"
REASONS = {
    "snapshotted": "Exact pinned bytes copied; recipient native review and sharing approval are still required.",
    "invalid_policy": "An independently retained lowercase SHA-256 plan pin is required.",
    "invalid_output": "Destination must be a new directory under an existing unlinked directory; nothing was copied.",
    "invalid_plan": "Plan must be bounded strict JSON with valid required slots and policies; source details withheld.",
    "plan_pin_mismatch": "Plan does not match the independent pin; no artifacts were read.",
    "path_conflict": "Required paths conflict with each other or the reserved collection-plan.json output name.",
    "invalid_artifact": "A required artifact is unreadable or is not bounded strict JSON; nothing was copied.",
    "artifact_pin_mismatch": "Required artifact bytes do not match the plan; nothing was copied.",
    "bundle_type_mismatch": "Required artifact type does not match the plan; nothing was copied.",
    "byte_budget_exceeded": "Required artifacts exceed the per-file or aggregate byte budget; nothing was copied.",
    "output_error": "Snapshot could not be completed; inspect the new destination for partial files. Existing destinations are never overwritten.",
}


def _directory(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
        raise ValueError("unlinked directory required")


def _destination(output: Path) -> Path:
    output = output.absolute()
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("destination already exists")
    for parent in output.parents:
        _directory(parent)
    return output


def _check_paths(entries: list[dict]) -> None:
    # Case-insensitive collisions matter even when exporting on a case-sensitive
    # filesystem: recipients must not need to rename paths and invalidate pins.
    directory_spellings = {}
    for entry in entries:
        parts = entry["path"].split("/")
        for end in range(1, len(parts)):
            spelling = "/".join(parts[:end])
            folded = spelling.casefold()
            if folded in directory_spellings and directory_spellings[folded] != spelling:
                raise ValueError("ambiguous parent directory casing")
            directory_spellings[folded] = spelling
    paths = [PLAN_FILENAME, *(entry["path"].casefold() for entry in entries)]
    for i, left in enumerate(paths):
        for right in paths[i + 1:]:
            if left == right or left.startswith(right + "/") or right.startswith(left + "/"):
                raise ValueError("conflicting file and directory paths")


def _write_new(path: Path, raw: bytes) -> None:
    # EXCL rejects existing files, links and dangling links. Restrictive POSIX
    # creation modes supplement, but do not replace, deployment-owned ACLs.
    with open(path, "xb", opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        if stream.write(raw) != len(raw):
            raise OSError("incomplete write")


def snapshot_collection(path: Path, output: Path, *, expected_plan_file_sha256: str) -> dict:
    """Copy every pinned input into a new directory, publishing the plan last.

    All inputs are admitted and snapshotted before output creation. No native
    verification, gh invocation, redaction, archive creation, or network transfer
    occurs. The transfer contains full original content, including private
    labels. Stable owner-controlled directories are required: these checks are
    not a race-proof filesystem sandbox or a durability guarantee.
    """
    receipt = {
        "schema_version": 1, "review_type": "ProofRun collection snapshot",
        "expected_plan_file_sha256": None, "plan_file_sha256": None,
        "required_entries": 0, "observed_entries": 0, "written_entries": 0,
        "artifact_bytes": 0, "failed_entry_index": None, "snapshot_complete": False,
        "artifact_evidence_verified": False, "requirements_completeness_established": False,
        "snapshot_is_approval": False,
        "snapshot_is_redacted": False,
    }

    def finish(reason, index=None):
        return {**receipt, "exit_code": 0 if reason == "snapshotted" else 2,
                "reason_code": reason, "failed_entry_index": index}

    if not _digest(expected_plan_file_sha256):
        return finish("invalid_policy")
    receipt["expected_plan_file_sha256"] = expected_plan_file_sha256
    try:
        path, output = Path(path), _destination(Path(output))
    except (OSError, TypeError, ValueError):
        return finish("invalid_output")
    try:
        plan_raw = read_regular_bytes(path, MAX_PLAN_BYTES)
        if len(plan_raw) > MAX_PLAN_BYTES:
            return finish("invalid_plan")
        receipt["plan_file_sha256"] = hashlib.sha256(plan_raw).hexdigest()
        if receipt["plan_file_sha256"] != expected_plan_file_sha256:
            return finish("plan_pin_mismatch")
        plan = decode_json_object(plan_raw, MAX_PLAN_BYTES)
        validate_plan(plan)
        root = path.resolve().parent
    except (OSError, TypeError, ValueError):
        return finish("invalid_plan")
    receipt["required_entries"] = len(plan["entries"])
    try:
        _check_paths(plan["entries"])
    except ValueError:
        return finish("path_conflict")
    remaining, snapshots = MAX_TOTAL_BYTES, []
    for index, entry in enumerate(plan["entries"]):
        if remaining <= 0:
            return finish("byte_budget_exceeded", index)
        limit = min(MAX_BUNDLE_BYTES, remaining)
        try:
            raw = read_regular_bytes(_entry_path(root, entry["path"]), limit)
            if len(raw) > limit:
                return finish("byte_budget_exceeded", index)
            remaining -= len(raw)
            if hashlib.sha256(raw).hexdigest() != entry["file_sha256"]:
                return finish("artifact_pin_mismatch", index)
            artifact = decode_json_object(raw, limit)
            if artifact.get("bundle_type") != entry["bundle_type"]:
                return finish("bundle_type_mismatch", index)
        except (OSError, TypeError, ValueError):
            return finish("invalid_artifact", index)
        snapshots.append((entry["path"], raw))
        receipt["observed_entries"] += 1
        receipt["artifact_bytes"] += len(raw)
    # Never reread after pin checking. These exact snapshots also preserve JSON
    # formatting/Unicode and the bytes used by external attestation subjects.
    writing_index = None
    try:
        _destination(output)
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
        for index, (relative, raw) in enumerate(snapshots):
            writing_index = index
            current = output
            _directory(current)
            for part in relative.split("/")[:-1]:
                current = current / part
                try:
                    current.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                _directory(current)
            _write_new(current / relative.split("/")[-1], raw)
            receipt["written_entries"] += 1
        writing_index = None
        _directory(output)
        _write_new(output / PLAN_FILENAME, plan_raw)
    except (OSError, TypeError, ValueError):
        return finish("output_error", writing_index)
    receipt["snapshot_complete"] = True
    return finish("snapshotted")


def render_snapshot(receipt: dict) -> str:
    lines = [REASONS[receipt["reason_code"]]]
    if receipt["failed_entry_index"] is not None:
        lines.append(f"Failed required entry: {receipt['failed_entry_index'] + 1}")
    lines.append(f"Required: {receipt['required_entries']}; observed: {receipt['observed_entries']}; written: {receipt['written_entries']}")
    if receipt["snapshot_complete"]:
        lines.append(f"Recipient plan: {PLAN_FILENAME}; exact plan SHA-256: {receipt['plan_file_sha256']}")
    lines.append("Snapshot files contain full original content, not redacted reports. Review before sharing; no upload performed.")
    return "\n".join(lines)
