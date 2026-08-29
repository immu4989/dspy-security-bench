"""Privacy-bounded public evidence bundles for verified cyber defense."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from typing import Any
from urllib.parse import urlparse

from dspy_security_bench.defend.protocol import DISCLAIMER, verify_report
from dspy_security_bench.mission.loader import canonical_sha256

BUNDLE_TYPE = "dspy-security-bench-defense-evidence"
DISCLOSURE_STATUSES = ("public-pattern", "embargoed", "private")
MAX_BUNDLE_BYTES = 5_000_000
_PROHIBITED = (
    '"prompt"',
    '"message_content"',
    '"chain_of_thought"',
    '"tool_arguments"',
    '"tool_results"',
    '"credentials"',
    '"exploit_payload"',
    '"live_target"',
)


@dataclass(frozen=True)
class DefenseEvidenceVerification:
    community_eligible: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


def build_evidence_bundle(
    report: dict[str, Any],
    *,
    submitter: str,
    runtime: str,
    source_repository: str,
    deployment_class: str,
    disclosure_status: str = "public-pattern",
    known_gaps: list[str] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    errors = verify_report(report)
    if errors:
        raise ValueError("invalid DefenderTwin report: " + "; ".join(errors))
    if disclosure_status not in DISCLOSURE_STATUSES:
        raise ValueError("unsupported disclosure_status")
    bundle: dict[str, Any] = {
        "schema_version": 1,
        "bundle_type": BUNDLE_TYPE,
        "submission": {
            "submitter": submitter,
            "runtime": runtime,
            "source_repository": source_repository,
            "deployment_class": deployment_class,
            "created_at": created_at or date.today().isoformat(),
            "disclosure_status": disclosure_status,
            "known_gaps": list(known_gaps or ["none-declared"]),
            "raw_data_shared": False,
        },
        "mission": report["mission"],
        "proposal": report["proposal"],
        "report": report,
        "claim_boundary": DISCLAIMER,
    }
    bundle["bundle_sha256"] = _digest(bundle)
    verification = verify_evidence_bundle(bundle)
    if verification.errors:
        raise ValueError("invalid generated defense evidence: " + "; ".join(verification.errors))
    return bundle


def verify_evidence_bundle(bundle: dict[str, Any]) -> DefenseEvidenceVerification:
    errors: list[str] = []
    warnings: list[str] = []
    if set(bundle) != {
        "schema_version",
        "bundle_type",
        "submission",
        "mission",
        "proposal",
        "report",
        "claim_boundary",
        "bundle_sha256",
    }:
        errors.append("defense evidence fields are incomplete or unsupported")
    if bundle.get("schema_version") != 1 or bundle.get("bundle_type") != BUNDLE_TYPE:
        errors.append("defense evidence metadata is unsupported")
    if bundle.get("claim_boundary") != DISCLAIMER:
        errors.append("defense evidence claim boundary changed")
    try:
        if bundle.get("bundle_sha256") != _digest(bundle):
            errors.append("bundle_sha256 does not match canonical bundle content")
        encoded = json.dumps(bundle, sort_keys=True, allow_nan=False).encode()
        serialized = encoded.decode().lower()
        if len(encoded) > MAX_BUNDLE_BYTES:
            errors.append(f"defense evidence exceeds {MAX_BUNDLE_BYTES} bytes")
        for token in _PROHIBITED:
            if token in serialized:
                errors.append(f"public bundle contains prohibited content field {token}")
    except (TypeError, ValueError):
        errors.append("defense evidence is not canonical JSON data")

    submission = bundle.get("submission")
    if not isinstance(submission, dict) or set(submission) != {
        "submitter",
        "runtime",
        "source_repository",
        "deployment_class",
        "created_at",
        "disclosure_status",
        "known_gaps",
        "raw_data_shared",
    }:
        errors.append("submission metadata fields are invalid")
    else:
        for field in ("submitter", "runtime", "deployment_class"):
            if (
                not isinstance(submission.get(field), str)
                or not submission[field].strip()
                or len(submission[field]) > 200
            ):
                errors.append(f"submission {field} must be a bounded non-empty string")
        parsed = urlparse(str(submission.get("source_repository", "")))
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or len(str(submission.get("source_repository", ""))) > 2048
        ):
            errors.append("submission source_repository must be an https URL")
        try:
            date.fromisoformat(str(submission.get("created_at", "")))
        except ValueError:
            errors.append("submission created_at must be an ISO date")
        if submission.get("disclosure_status") not in DISCLOSURE_STATUSES:
            errors.append("submission disclosure_status is unsupported")
        if submission.get("raw_data_shared") is not False:
            errors.append("public defense evidence must declare raw_data_shared false")
        gaps = submission.get("known_gaps")
        if (
            not isinstance(gaps, list)
            or not gaps
            or len(gaps) > 100
            or not all(isinstance(item, str) and item.strip() and len(item) <= 300 for item in gaps)
        ):
            errors.append("submission known_gaps must contain bounded non-empty strings")
        if submission.get("disclosure_status") != "public-pattern":
            warnings.append("only public-pattern evidence is eligible for the public registry")

    report = bundle.get("report")
    if not isinstance(report, dict):
        errors.append("report must be an object")
    else:
        errors.extend(verify_report(report))
        if bundle.get("mission") != report.get("mission"):
            errors.append("bundle mission is not bound to the report")
        if bundle.get("proposal") != report.get("proposal"):
            errors.append("bundle proposal is not bound to the report")
        if report.get("summary", {}).get("evidence_complete") is not True:
            warnings.append("required evidence is incomplete")
    return DefenseEvidenceVerification(not errors and not warnings, tuple(errors), tuple(warnings))


def _digest(bundle: dict[str, Any]) -> str:
    return canonical_sha256({key: value for key, value in bundle.items() if key != "bundle_sha256"})
