"""Content-addressed community bundles for CausalProof evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any
from urllib.parse import urlparse

from dspy_security_bench.causal.proof import (
    DISCLAIMER,
    analyze_causality,
    structural_trace,
    verify_causal_report,
)
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.schedule.proof import analyze_scenario, verify_schedule_report

BUNDLE_TYPE = "dspy-security-bench-causal-submission"


@dataclass(frozen=True)
class CausalSubmissionResult:
    community_eligible: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


def build_causal_submission_bundle(
    trace: dict[str, Any],
    manifest: dict[str, Any],
    *,
    submitter: str,
    runtime: str,
    source_repository: str,
    known_gaps: list[str] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build a public bundle that contains no OTLP content-bearing fields."""

    structural = structural_trace(trace)
    causal_report = analyze_causality(structural, manifest)
    if causal_report["schedule_scenario"] is None:
        raise ValueError("CausalProof did not produce a valid ScheduleProof scenario")
    schedule_report = analyze_scenario(causal_report["schedule_scenario"])
    bundle: dict[str, Any] = {
        "schema_version": 1,
        "bundle_type": BUNDLE_TYPE,
        "submission": {
            "submitter": submitter,
            "runtime": runtime,
            "source_repository": source_repository,
            "created_at": created_at or date.today().isoformat(),
            "known_gaps": list(known_gaps or ["none declared"]),
        },
        "structural_trace": structural,
        "manifest": manifest,
        "causal_report": causal_report,
        "schedule_report": schedule_report,
        "claim_boundary": DISCLAIMER,
    }
    bundle["bundle_sha256"] = _bundle_digest(bundle)
    result = verify_causal_submission_bundle(bundle)
    if result.errors:
        raise ValueError("invalid generated causal submission: " + "; ".join(result.errors))
    return bundle


def verify_causal_submission_bundle(bundle: dict[str, Any]) -> CausalSubmissionResult:
    """Recompute the full trace → causal graph → schedule evidence chain."""

    errors: list[str] = []
    warnings: list[str] = []
    fields = {
        "schema_version",
        "bundle_type",
        "submission",
        "structural_trace",
        "manifest",
        "causal_report",
        "schedule_report",
        "claim_boundary",
        "bundle_sha256",
    }
    if set(bundle) != fields:
        errors.append("causal submission fields are incomplete or unsupported")
    if bundle.get("schema_version") != 1 or bundle.get("bundle_type") != BUNDLE_TYPE:
        errors.append("causal submission metadata is unsupported")
    if bundle.get("claim_boundary") != DISCLAIMER:
        errors.append("causal submission claim boundary changed")
    if bundle.get("bundle_sha256") != _bundle_digest(bundle):
        errors.append("bundle_sha256 does not match canonical bundle content")

    submission = bundle.get("submission")
    if not isinstance(submission, dict) or set(submission) != {
        "submitter", "runtime", "source_repository", "created_at", "known_gaps"
    }:
        errors.append("submission metadata fields are invalid")
    else:
        for field in ("submitter", "runtime"):
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
        if not isinstance(gaps, list) or not gaps or not all(
            isinstance(item, str) and item.strip() and len(item) <= 300 for item in gaps
        ):
            errors.append("submission known_gaps must contain bounded non-empty strings")

    structural = bundle.get("structural_trace")
    manifest = bundle.get("manifest")
    causal_report = bundle.get("causal_report")
    schedule_report = bundle.get("schedule_report")
    if not all(isinstance(item, dict) for item in (
        structural, manifest, causal_report, schedule_report
    )):
        errors.append("causal submission evidence members must be objects")
    else:
        if structural_trace(structural) != structural:
            errors.append("structural_trace contains unsupported or non-canonical fields")
        errors.extend(verify_causal_report(causal_report, structural, manifest))
        errors.extend(verify_schedule_report(schedule_report))
        if causal_report.get("schedule_scenario") != schedule_report.get("scenario"):
            errors.append("schedule report is not bound to the CausalProof draft")
        if causal_report.get("summary", {}).get("status") != "ready":
            warnings.append("CausalProof reports instrumentation gaps requiring human review")
    return CausalSubmissionResult(not errors and not warnings, tuple(errors), tuple(warnings))


def _bundle_digest(bundle: dict[str, Any]) -> str:
    return canonical_sha256({key: value for key, value in bundle.items() if key != "bundle_sha256"})
