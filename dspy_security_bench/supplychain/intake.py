"""One-command, reproducible AI supplier disclosure intake packs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.aibom_policy import (
    ai_disclosure_policy_report_to_sarif,
    build_ai_disclosure_policy_report,
)
from dspy_security_bench.supplychain.mlbom import build_mlbom_import_report
from dspy_security_bench.supplychain.spdxai import build_spdx_ai_import_report

PACK_TYPE = "dspy-security-bench-ai-disclosure-intake"
PACK_FILES = (
    "cyclonedx.report.json",
    "spdx.report.json",
    "policy.report.json",
    "policy.sarif",
    "review.md",
    "manifest.json",
)
MAX_FILE_BYTES = 15_000_000


def build_intake_artifacts(
    policy: Mapping[str, Any],
    cyclonedx_source: Mapping[str, Any],
    spdx_source: Mapping[str, Any],
) -> dict[str, bytes]:
    """Build a fixed six-file pack without copying the original BOMs or policy."""
    cdx = build_mlbom_import_report(cyclonedx_source, inventory_id="intake-cyclonedx")
    spdx = build_spdx_ai_import_report(spdx_source, inventory_id="intake-spdx")
    report = build_ai_disclosure_policy_report(policy, cdx, cyclonedx_source, spdx, spdx_source)
    artifacts = {
        "cyclonedx.report.json": _json_bytes(cdx),
        "spdx.report.json": _json_bytes(spdx),
        "policy.report.json": _json_bytes(report),
        "policy.sarif": _json_bytes(ai_disclosure_policy_report_to_sarif(report)),
        "review.md": _review_markdown(report).encode("utf-8"),
    }
    manifest = {
        "schema_version": 1,
        "pack_type": PACK_TYPE,
        "policy_sha256": canonical_sha256(policy),
        "cyclonedx_source_sha256": canonical_sha256(cyclonedx_source),
        "spdx_source_sha256": canonical_sha256(spdx_source),
        "evaluation_report_sha256": report["report_sha256"],
        "status": report["summary"]["status"],
        "finding_count": report["summary"]["finding_count"],
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in artifacts.items()},
        "source_documents_included": False,
        "supplier_authenticated": False,
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    artifacts["manifest.json"] = _json_bytes(manifest)
    if any(len(data) > MAX_FILE_BYTES for data in artifacts.values()):
        raise ValueError("intake artifact exceeds the supported file size")
    return artifacts


def write_intake_pack(
    destination: Path,
    policy: Mapping[str, Any],
    cyclonedx_source: Mapping[str, Any],
    spdx_source: Mapping[str, Any],
) -> dict[str, Any]:
    """Create a fresh directory after computing all content; never overwrite."""
    artifacts = build_intake_artifacts(policy, cyclonedx_source, spdx_source)
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in artifacts.items():
        with (destination / name).open("xb") as stream:
            stream.write(data)
    return json.loads(artifacts["manifest.json"])


def verify_intake_pack(
    destination: Path,
    policy: Mapping[str, Any],
    cyclonedx_source: Mapping[str, Any],
    spdx_source: Mapping[str, Any],
) -> tuple[str, ...]:
    """Rebuild every artifact from retained inputs and compare the exact bytes."""
    try:
        expected = build_intake_artifacts(policy, cyclonedx_source, spdx_source)
        if destination.is_symlink() or not destination.is_dir():
            return ("intake pack must be a directory and not a symbolic link",)
        if {path.name for path in destination.iterdir()} != set(PACK_FILES):
            return ("intake pack must contain exactly the six declared files",)
        errors = []
        for name, data in expected.items():
            path = destination / name
            if path.is_symlink() or not path.is_file():
                errors.append(f"{name} must be a regular file and not a symbolic link")
                continue
            with path.open("rb") as stream:
                actual = stream.read(MAX_FILE_BYTES + 1)
            if actual != data:
                errors.append(f"{name} does not exactly recompute from retained inputs")
        return tuple(errors)
    except (OSError, ValueError, TypeError) as exc:
        return (f"intake pack cannot be verified: {exc}",)


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def _review_markdown(report: Mapping[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# AI disclosure intake review",
        "",
        f"Result: `{summary['status']}`. Findings: {summary['finding_count']}.",
        "",
        "This review checks the supplied owner's structural disclosure requirements.",
        "It does not authenticate the supplier or assess whether disclosure values are true or adequate.",
        "",
        "| Standard | Component | Requirement | Count |",
        "| --- | --- | --- | --- |",
    ]
    for item in report["findings"]:
        requirement = item["field"] or item["finding_type"]
        lines.append(
            f"| {item['standard']} | `{item['component_id']}` | `{requirement}` | {item['count']} |"
        )
    lines.extend(
        [
            "",
            "Retain the original policy and both BOM source documents separately for verification.",
            "The pack contains hashes and field-presence evidence, which still require a sharing review.",
            "Use `dspy-security-bench bom verify-ai-intake` with those original inputs to reproduce every file.",
            "",
        ]
    )
    return "\n".join(lines)
