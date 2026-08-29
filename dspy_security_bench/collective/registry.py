"""Content-addressed public registry bundles for CollectiveGuard v2 evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any
from urllib.parse import urlparse

from dspy_security_bench.collective.v2 import (
    DISCLAIMER,
    analyze_scenario_v2,
    validate_scenario,
    verify_report,
)
from dspy_security_bench.mission.loader import canonical_sha256

BUNDLE_TYPE = "dspy-security-bench-collective-submission"


@dataclass(frozen=True)
class CollectiveSubmissionResult:
    community_eligible: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


def build_collective_submission_bundle(
    scenario: dict[str, Any],
    *,
    submitter: str,
    runtime: str,
    source_repository: str,
    deployment_class: str,
    known_gaps: list[str] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    errors = validate_scenario(scenario)
    if errors:
        raise ValueError("invalid CollectiveGuard v2 scenario: " + "; ".join(errors))
    report = analyze_scenario_v2(scenario)
    bundle: dict[str, Any] = {
        "schema_version": 1,
        "bundle_type": BUNDLE_TYPE,
        "submission": {
            "submitter": submitter,
            "runtime": runtime,
            "source_repository": source_repository,
            "deployment_class": deployment_class,
            "created_at": created_at or date.today().isoformat(),
            "known_gaps": list(known_gaps or ["none declared"]),
        },
        "scenario": scenario,
        "report": report,
        "claim_boundary": DISCLAIMER,
    }
    bundle["bundle_sha256"] = _digest(bundle)
    result = verify_collective_submission_bundle(bundle)
    if result.errors:
        raise ValueError("invalid generated collective submission: " + "; ".join(result.errors))
    return bundle


def verify_collective_submission_bundle(bundle: dict[str, Any]) -> CollectiveSubmissionResult:
    errors: list[str] = []
    warnings: list[str] = []
    fields = {
        "schema_version",
        "bundle_type",
        "submission",
        "scenario",
        "report",
        "claim_boundary",
        "bundle_sha256",
    }
    if set(bundle) != fields:
        errors.append("collective submission fields are incomplete or unsupported")
    if bundle.get("schema_version") != 1 or bundle.get("bundle_type") != BUNDLE_TYPE:
        errors.append("collective submission metadata is unsupported")
    if bundle.get("claim_boundary") != DISCLAIMER:
        errors.append("collective submission claim boundary changed")
    try:
        if bundle.get("bundle_sha256") != _digest(bundle):
            errors.append("bundle_sha256 does not match canonical bundle content")
    except (TypeError, ValueError):
        errors.append("bundle is not canonical JSON data")

    submission = bundle.get("submission")
    if not isinstance(submission, dict) or set(submission) != {
        "submitter",
        "runtime",
        "source_repository",
        "deployment_class",
        "created_at",
        "known_gaps",
    }:
        errors.append("submission metadata fields are invalid")
    else:
        for field in ("submitter", "runtime", "deployment_class"):
            if not isinstance(submission.get(field), str) or not submission[field].strip():
                errors.append(f"submission {field} must be a non-empty string")
        source = submission.get("source_repository")
        parsed = urlparse(source if isinstance(source, str) else "")
        if parsed.scheme != "https" or not parsed.netloc:
            errors.append("submission source_repository must be an https URL")
        try:
            date.fromisoformat(str(submission.get("created_at", "")))
        except ValueError:
            errors.append("submission created_at must be an ISO date")
        gaps = submission.get("known_gaps")
        if (
            not isinstance(gaps, list)
            or not gaps
            or not all(isinstance(item, str) and item.strip() and len(item) <= 300 for item in gaps)
        ):
            errors.append("submission known_gaps must contain bounded non-empty strings")

    scenario, report = bundle.get("scenario"), bundle.get("report")
    if not isinstance(scenario, dict) or not isinstance(report, dict):
        errors.append("collective submission scenario and report must be objects")
    else:
        errors.extend(f"scenario: {item}" for item in validate_scenario(scenario))
        errors.extend(f"report: {item}" for item in verify_report(report))
        if report.get("scenario") != scenario:
            errors.append("report is not bound to the submitted scenario")
        if report.get("summary", {}).get("status") == "insufficient_evidence":
            warnings.append(
                "CollectiveGuard reports insufficient evidence for a clean-result claim"
            )
        if any(
            item.get("collection_status") != "complete"
            for item in scenario.get("sources", [])
            if isinstance(item, dict)
        ):
            warnings.append("one or more declared evidence sources are incomplete")
    return CollectiveSubmissionResult(not errors and not warnings, tuple(errors), tuple(warnings))


def _digest(bundle: dict[str, Any]) -> str:
    return canonical_sha256({key: value for key, value in bundle.items() if key != "bundle_sha256"})
