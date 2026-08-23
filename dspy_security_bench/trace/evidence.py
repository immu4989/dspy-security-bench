"""Content-addressed community bundles for privacy-bounded TraceProof evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.trace.mcp import verify_mcp_authorization_report
from dspy_security_bench.trace.proof import (
    analyze_trace_evidence,
    verify_trace_evidence,
    verify_trace_report,
)

BUNDLE_TYPE = "dspy-security-bench-traceproof-community-evidence"
DISCLAIMER = (
    "Registry admission establishes only that sanitized evidence and deterministic findings "
    "recompute under the declared TraceProof protocol. It does not establish telemetry "
    "completeness, independent execution, system safety, compliance, certification, government "
    "endorsement, or authorization to operate. Never submit raw production telemetry."
)


@dataclass(frozen=True)
class TraceSubmissionVerification:
    community_eligible: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


def build_trace_submission_bundle(
    evidence: Mapping[str, Any],
    report: Mapping[str, Any],
    *,
    submitter: str,
    runtime: str,
    source_repository_url: str,
    notes: str = "",
    mcp_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _submission_text("submitter", submitter, 128)
    _submission_text("runtime", runtime, 128)
    _submission_text("notes", notes, 1000, allow_empty=True)
    _https_url("source_repository_url", source_repository_url)
    evidence_errors = verify_trace_evidence(evidence)
    if evidence_errors:
        raise ValueError("invalid TraceProof evidence: " + "; ".join(evidence_errors))
    expected_report = analyze_trace_evidence(evidence)
    if report != expected_report:
        raise ValueError("TraceProof report does not recompute from evidence")
    mcp = None
    if mcp_report is not None:
        mcp_errors = verify_mcp_authorization_report(mcp_report, evidence)
        if mcp_errors:
            raise ValueError("invalid MCP probe report: " + "; ".join(mcp_errors))
        mcp = dict(mcp_report)
    bundle: dict[str, Any] = {
        "schema_version": 1,
        "bundle_type": BUNDLE_TYPE,
        "evidence": dict(evidence),
        "report": dict(report),
        "mcp_report": mcp,
        "submission": {
            "submitter": submitter.strip(),
            "runtime": runtime.strip(),
            "source_repository_url": source_repository_url.strip(),
            "notes": notes.strip(),
            "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "privacy_attestation": (
                "submitter reviewed the sanitized bundle and did not include raw telemetry"
            ),
        },
        "provenance": {
            "provider": "self_attested",
            "evidence_tier": "self_attested",
        },
        "disclaimer": DISCLAIMER,
    }
    bundle["bundle_sha256"] = canonical_sha256(bundle)
    verification = verify_trace_submission_bundle(bundle)
    if verification.errors:
        raise ValueError(
            "generated TraceProof bundle is invalid: " + "; ".join(verification.errors)
        )
    return bundle


def verify_trace_submission_bundle(
    bundle: Mapping[str, Any],
) -> TraceSubmissionVerification:
    errors: list[str] = []
    warnings: list[str] = []
    fields = {
        "schema_version",
        "bundle_type",
        "evidence",
        "report",
        "mcp_report",
        "submission",
        "provenance",
        "disclaimer",
        "bundle_sha256",
    }
    if set(bundle) != fields:
        errors.append("TraceProof bundle fields are incomplete or unsupported")
    if (
        bundle.get("schema_version") != 1
        or bundle.get("bundle_type") != BUNDLE_TYPE
        or bundle.get("disclaimer") != DISCLAIMER
    ):
        errors.append("TraceProof bundle metadata does not match the registry protocol")
    evidence = bundle.get("evidence")
    report = bundle.get("report")
    if not isinstance(evidence, Mapping):
        errors.append("TraceProof bundle evidence must be an object")
    else:
        errors.extend(f"evidence: {item}" for item in verify_trace_evidence(evidence))
    if not isinstance(report, Mapping):
        errors.append("TraceProof bundle report must be an object")
    else:
        errors.extend(f"report: {item}" for item in verify_trace_report(report))
    if isinstance(evidence, Mapping) and isinstance(report, Mapping):
        try:
            expected = analyze_trace_evidence(evidence)
        except (TypeError, ValueError) as exc:
            errors.append(f"report cannot recompute from evidence: {exc}")
        else:
            if report != expected:
                errors.append("TraceProof report does not recompute from bundled evidence")
    mcp_report = bundle.get("mcp_report")
    if mcp_report is not None:
        if not isinstance(mcp_report, Mapping) or not isinstance(evidence, Mapping):
            errors.append("MCP report requires bundled TraceProof evidence")
        else:
            errors.extend(
                f"mcp_report: {item}"
                for item in verify_mcp_authorization_report(mcp_report, evidence)
            )
    submission = bundle.get("submission")
    submission_fields = {
        "submitter",
        "runtime",
        "source_repository_url",
        "notes",
        "created_at",
        "privacy_attestation",
    }
    if not isinstance(submission, Mapping) or set(submission) != submission_fields:
        errors.append("TraceProof submission metadata is incomplete or unsupported")
    else:
        for field, limit, allow_empty in (
            ("submitter", 128, False),
            ("runtime", 128, False),
            ("notes", 1000, True),
            ("created_at", 64, False),
        ):
            try:
                _submission_text(field, submission.get(field), limit, allow_empty=allow_empty)
            except ValueError as exc:
                errors.append(str(exc))
        try:
            _https_url("source_repository_url", submission.get("source_repository_url"))
        except ValueError as exc:
            errors.append(str(exc))
        created_at = submission.get("created_at")
        if isinstance(created_at, str):
            try:
                parsed_created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except ValueError:
                errors.append("submission created_at must be an ISO 8601 timestamp")
            else:
                if parsed_created_at.tzinfo is None:
                    errors.append("submission created_at must include a timezone")
        if submission.get("privacy_attestation") != (
            "submitter reviewed the sanitized bundle and did not include raw telemetry"
        ):
            errors.append("TraceProof privacy_attestation does not match the registry contract")
    provenance = bundle.get("provenance")
    if provenance != {"provider": "self_attested", "evidence_tier": "self_attested"}:
        errors.append("TraceProof v1 bundles must declare self_attested provenance")
    unsigned = dict(bundle)
    claimed = unsigned.pop("bundle_sha256", None)
    try:
        actual = canonical_sha256(unsigned)
    except (TypeError, ValueError):
        actual = None
    if claimed != actual:
        errors.append("TraceProof bundle_sha256 does not match canonical content")
    if isinstance(evidence, Mapping) and _reference_fixture(evidence):
        warnings.append("maintainer synthetic/reference telemetry is not registry eligible")
    eligible = not errors and not warnings
    return TraceSubmissionVerification(eligible, tuple(dict.fromkeys(errors)), tuple(warnings))


def _reference_fixture(evidence: Mapping[str, Any]) -> bool:
    names = {
        str(span.get("resource", {}).get("service.name", ""))
        for span in evidence.get("spans", [])
        if isinstance(span, Mapping)
    }
    markers = (
        "claims-demo",
        "traceproof-redaction-challenge",
        "traceproof-runtime-demo",
        "traceproof-reference-lab",
    )
    return any(any(marker in name for marker in markers) for name in names)


def _submission_text(field: str, value: Any, limit: int, *, allow_empty: bool = False) -> None:
    if not isinstance(value, str) or len(value) > limit or (not allow_empty and not value.strip()):
        suffix = " or empty" if allow_empty else ""
        raise ValueError(f"submission {field} must be a string up to {limit} characters{suffix}")
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise ValueError(f"submission {field} contains unsupported control characters")


def _https_url(field: str, value: Any) -> None:
    if not isinstance(value, str) or len(value) > 500:
        raise ValueError(f"submission {field} must be an HTTPS URL")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError(f"submission {field} must be an HTTPS URL without credentials")
