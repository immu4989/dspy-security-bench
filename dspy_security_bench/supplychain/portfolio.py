"""Bounded offline intake of multiple AI suppliers under one owner policy."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from dspy_security_bench.jsonio import read_json_object
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.aibom_policy import compare_ai_disclosure_policies
from dspy_security_bench.supplychain.intake import MAX_FILE_BYTES, build_intake_artifacts

MANIFEST_TYPE = "dspy-security-bench-ai-supplier-portfolio"
MAX_SUPPLIERS = 25
MAX_SOURCE_BYTES = 2_000_000
MAX_OUTPUT_BYTES = 100_000_000
_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
CLAIM_BOUNDARY = (
    "This portfolio evaluates structural disclosures under one supplied owner policy. "
    "Supplier IDs are owner-assigned labels, not authenticated identities. A requirements_met "
    "result is not a security score, ranking, legal finding, procurement approval, or authorization "
    "to operate. Missing or malformed submissions are input_invalid, never zero-finding passes. "
    "The input manifest, policy, and sources must be retained independently for reproduction."
)


def build_portfolio_artifacts(
    manifest: Mapping[str, Any], policy: Mapping[str, Any], source_root: Path
) -> dict[str, bytes]:
    """Evaluate up to 25 explicitly labeled submissions; never fetch remote data."""
    entries = _parse_manifest(manifest)
    # Reject a bad common policy before handling per-submission failures.
    compare_ai_disclosure_policies(policy, policy)
    root = source_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("portfolio source root must be a directory")
    artifacts: dict[str, bytes] = {}
    rows = []
    total_bytes = 0
    for entry in entries:
        row: dict[str, Any] = {
            "supplier_id": entry["supplier_id"],
            "status": "input_invalid",
            "finding_count": None,
            "intake_manifest_sha256": None,
            "error_code": None,
        }
        try:
            cdx = _read_source(root, entry["cyclonedx_source"])
            spdx = _read_source(root, entry["spdx_source"])
        except (OSError, ValueError, RuntimeError):
            # Do not publish private paths, source fields, or exception details.
            row["error_code"] = "source_unreadable_or_invalid_json"
        else:
            try:
                pack = build_intake_artifacts(policy, cdx, spdx)
            except (TypeError, ValueError):
                row["error_code"] = "unsupported_or_invalid_disclosure"
            else:
                total_bytes += sum(len(data) for data in pack.values())
                if total_bytes > MAX_OUTPUT_BYTES:
                    raise ValueError("portfolio output exceeds the total byte budget")
                intake = json.loads(pack["manifest.json"])
                row.update(
                    status=intake["status"],
                    finding_count=intake["finding_count"],
                    intake_manifest_sha256=intake["manifest_sha256"],
                )
                for name, data in pack.items():
                    artifacts[f"suppliers/{entry['supplier_id']}/{name}"] = data
        rows.append(row)
    invalid = sum(row["status"] == "input_invalid" for row in rows)
    review = sum(row["status"] == "owner_review_required" for row in rows)
    report = {
        "schema_version": 1,
        "report_type": "AgentBOM AI supplier portfolio",
        "protocol_version": "agentbom-ai-portfolio-v1",
        "submission_manifest_sha256": canonical_sha256(manifest),
        "policy_sha256": canonical_sha256(policy),
        "suppliers": rows,
        "summary": {
            "suppliers": len(rows),
            "evaluated": len(rows) - invalid,
            "input_invalid": invalid,
            "owner_review_required": review,
            "requirements_met": len(rows) - invalid - review,
            "finding_count": sum(row["finding_count"] or 0 for row in rows),
            "complete": invalid == 0,
            "automatic_approvals": 0,
        },
        "files": {
            name: hashlib.sha256(data).hexdigest() for name, data in sorted(artifacts.items())
        },
        "claim_boundary": CLAIM_BOUNDARY,
    }
    report["report_sha256"] = canonical_sha256(report)
    artifacts["portfolio.json"] = _json_bytes(report)
    artifacts["review.md"] = _review(report).encode("utf-8")
    return artifacts


def write_portfolio_pack(
    destination: Path, manifest: Mapping[str, Any], policy: Mapping[str, Any], source_root: Path
) -> dict[str, Any]:
    """Write computed evidence to a fresh directory without overwriting anything."""
    artifacts = build_portfolio_artifacts(manifest, policy, source_root)
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in artifacts.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    return json.loads(artifacts["portfolio.json"])


def verify_portfolio_pack(
    destination: Path, manifest: Mapping[str, Any], policy: Mapping[str, Any], source_root: Path
) -> tuple[str, ...]:
    """Recompute every file and directory, including partial-intake status."""
    expected = build_portfolio_artifacts(manifest, policy, source_root)
    if destination.is_symlink() or not destination.is_dir():
        return ("portfolio must be a directory, not a symbolic link",)
    expected_dirs = {
        str(parent)
        for name in expected
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
    }
    seen_files, seen_dirs = set(), set()
    try:
        # Explicit traversal never follows symlinks, including unexpected dirs.
        pending = [destination]
        while pending:
            directory = pending.pop()
            for path in directory.iterdir():
                name = path.relative_to(destination).as_posix()
                if path.is_symlink():
                    return ("portfolio must not contain symbolic links",)
                if path.is_dir():
                    if name not in expected_dirs:
                        return ("portfolio contains an unexpected directory",)
                    seen_dirs.add(name)
                    pending.append(path)
                elif path.is_file() and name in expected:
                    seen_files.add(name)
                    with path.open("rb") as stream:
                        if stream.read(MAX_FILE_BYTES + 1) != expected[name]:
                            return ("portfolio file does not exactly recompute",)
                else:
                    return ("portfolio contains an unexpected or non-regular file",)
        if seen_files != set(expected) or seen_dirs != expected_dirs:
            return ("portfolio is missing required files or directories",)
    except OSError:
        return ("portfolio cannot be read",)
    return ()


def _parse_manifest(manifest: Mapping[str, Any]) -> list[dict[str, str]]:
    if not isinstance(manifest, Mapping) or set(manifest) != {
        "schema_version",
        "manifest_type",
        "suppliers",
    }:
        raise ValueError(
            "portfolio manifest must contain only schema_version, manifest_type, suppliers"
        )
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["manifest_type"] != MANIFEST_TYPE
    ):
        raise ValueError("unsupported portfolio manifest")
    suppliers = manifest["suppliers"]
    if not isinstance(suppliers, list) or not 1 <= len(suppliers) <= MAX_SUPPLIERS:
        raise ValueError(f"portfolio must contain 1 to {MAX_SUPPLIERS} suppliers")
    seen = set()
    result = []
    for entry in suppliers:
        if not isinstance(entry, Mapping) or set(entry) != {
            "supplier_id",
            "cyclonedx_source",
            "spdx_source",
        }:
            raise ValueError("supplier entry has missing or unknown fields")
        label = entry["supplier_id"]
        if (
            not isinstance(label, str)
            or len(label) > 64
            or not _ID.fullmatch(label)
            or label in seen
        ):
            raise ValueError("supplier IDs must be unique lowercase slugs of at most 64 characters")
        seen.add(label)
        for field in ("cyclonedx_source", "spdx_source"):
            value = entry[field]
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 1024
                or "\\" in value
                or "\x00" in value
            ):
                raise ValueError("source paths must be bounded relative POSIX paths")
            if PurePosixPath(value).is_absolute() or any(
                part in {"", ".", ".."} for part in value.split("/")
            ):
                raise ValueError("source paths must be relative without dot segments")
        result.append(dict(entry))
    return sorted(result, key=lambda entry: entry["supplier_id"])


def _read_source(root: Path, relative: str) -> dict[str, Any]:
    path = root.joinpath(*PurePosixPath(relative).parts).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("source must resolve to a regular file inside the source root")
    return read_json_object(path, MAX_SOURCE_BYTES)


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def _review(report: Mapping[str, Any]) -> str:
    lines = [
        "# AI supplier portfolio review",
        "",
        CLAIM_BOUNDARY,
        "",
        "| Owner supplier ID | Structural result | Findings | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for row in report["suppliers"]:
        label = row["supplier_id"]
        count = row["finding_count"] if row["finding_count"] is not None else "not evaluated"
        evidence = (
            f"[review](suppliers/{label}/review.md)"
            if row["intake_manifest_sha256"]
            else row["error_code"]
        )
        lines.append(f"| `{label}` | `{row['status']}` | {count} | {evidence} |")
    lines.extend(
        [
            "",
            "All evaluated suppliers use the same policy digest:",
            f"`{report['policy_sha256']}`",
            "",
            "A count of zero does not imply adequacy or safety. Invalid submissions have no finding count.",
            "",
        ]
    )
    return "\n".join(lines)
