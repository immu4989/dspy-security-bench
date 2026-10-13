"""Typed, source-redacted metadata preflight for structural public evidence.

This validates declarations only. Native verifiers must still recompute every
embedded report and enforce their own disclosure/eligibility boundaries.
"""

import json
import re
from collections.abc import Mapping
from datetime import date, datetime, timezone

from dspy_security_bench.procurement.submission_metadata import _https_reference

PRIVACY_ATTESTATION = "submitter reviewed the sanitized bundle and did not include raw telemetry"
_COMMON = {"submitter", "runtime", "created_at"}
_FIELDS = {
    "trace": _COMMON | {"source_repository_url", "notes", "privacy_attestation"},
    "causal": _COMMON | {"source_repository", "known_gaps"},
    "collective": _COMMON | {"source_repository", "known_gaps", "deployment_class"},
    "defense": _COMMON | {"source_repository", "known_gaps", "deployment_class", "disclosure_status", "raw_data_shared"},
}
_BUNDLE_TYPES = {
    "trace": "dspy-security-bench-traceproof-community-evidence",
    "causal": "dspy-security-bench-causal-submission",
    "collective": "dspy-security-bench-collective-submission",
    "defense": "dspy-security-bench-defense-evidence",
}
_BUNDLE_MEMBERS = {
    "trace": {"evidence", "report", "mcp_report", "provenance", "disclaimer"},
    "causal": {"structural_trace", "manifest", "causal_report", "schedule_report", "claim_boundary"},
    "collective": {"scenario", "report", "claim_boundary"},
    "defense": {"mission", "proposal", "report", "claim_boundary"},
}


def validate_submission(submission, *, family: str) -> tuple[str, ...]:
    required = _FIELDS[family]
    if not isinstance(submission, Mapping) or set(submission) != required:
        return ("submission metadata fields are incomplete or unsupported; source field names withheld",)
    errors = []
    for field in sorted(required - {"known_gaps", "raw_data_shared"}):
        value = submission[field]
        if not isinstance(value, str) or (field != "notes" and not value.strip()):
            errors.append(f"submission.{field} must be a string" + ("" if field == "notes" else " and non-empty"))
    limits = ({"submitter": 128, "runtime": 128, "notes": 1000, "created_at": 64,
               "source_repository_url": 500} if family == "trace" else
              {"submitter": 200, "runtime": 200, "deployment_class": 200, "source_repository": 2048}
              if family == "defense" else {})
    for field, limit in limits.items():
        if isinstance(submission[field], str) and len(submission[field]) > limit:
            errors.append(f"submission.{field} must be a bounded " + ("string" if field == "notes" else "non-empty string"))
    source_field = "source_repository_url" if family == "trace" else "source_repository"
    if not _https_reference(submission[source_field]):
        errors.append(f"submission.{source_field} must be an https URL without credentials")
    stamp = submission["created_at"]
    try:
        if not isinstance(stamp, str):
            raise ValueError("timestamp must be text")
        if family == "trace":
            if "T" not in stamp or datetime.fromisoformat(stamp.replace("Z", "+00:00")).utcoffset() is None:
                raise ValueError("timezone required")
        elif date.fromisoformat(stamp).isoformat() != stamp:
            raise ValueError("extended ISO date required")
    except ValueError:
        errors.append("submission.created_at must include a timezone and be an ISO timestamp" if family == "trace"
                      else "submission.created_at must be a YYYY-MM-DD date string")
    if family == "trace":
        if submission["privacy_attestation"] != PRIVACY_ATTESTATION:
            errors.append("submission.privacy_attestation does not match the registry contract")
    else:
        gaps = submission["known_gaps"]
        if (not isinstance(gaps, list) or not gaps
                or not all(isinstance(item, str) and item.strip() and len(item) <= 300 for item in gaps)
                or (family == "defense" and len(gaps) > 100)):
            errors.append("submission.known_gaps must contain bounded non-empty strings")
    if family == "defense":
        if submission["disclosure_status"] not in ("public-pattern", "embargoed", "private"):
            errors.append("submission.disclosure_status is unsupported")
        if submission["raw_data_shared"] is not False:
            errors.append("submission.raw_data_shared must be false")
    if not errors:
        try:
            json.dumps(dict(submission), ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            errors.append("submission metadata must be portable UTF-8 JSON; source details withheld")
    return tuple(errors)


def validate_bundle_metadata(bundle, *, family: str) -> tuple[str, ...]:
    if not isinstance(bundle, Mapping):
        return ("submission bundle must be an object",)
    errors = []
    fields = {"schema_version", "bundle_type", "submission", "bundle_sha256"} | _BUNDLE_MEMBERS[family]
    if set(bundle) != fields:
        errors.append("bundle fields are incomplete or unsupported; source field names withheld")
    if bundle.get("bundle_type") != _BUNDLE_TYPES[family]:
        errors.append("bundle_type does not match the registry protocol")
    if type(bundle.get("schema_version")) is not int or bundle["schema_version"] != 1:
        errors.append("schema_version must be integer 1")
    digest = bundle.get("bundle_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        errors.append("bundle_sha256 must be lowercase SHA-256")
    errors.extend(validate_submission(bundle.get("submission"), family=family))
    if family == "trace" and bundle.get("provenance") != {"provider": "self_attested", "evidence_tier": "self_attested"}:
        errors.append("TraceProof provenance must remain self-attested")
    boundary = bundle.get("disclaimer" if family == "trace" else "claim_boundary")
    try:
        if not isinstance(boundary, str) or not boundary:
            raise ValueError("boundary must be text")
        boundary.encode("utf-8")
    except (ValueError, UnicodeError):
        errors.append("claim boundary must be portable non-empty UTF-8 text")
    return tuple(errors)


def prepare_submission(*, family, submitter, runtime, source_repository, created_at=None,
                       known_gaps=None, deployment_class=None, notes="", disclosure_status="public-pattern") -> dict:
    submission = {"submitter": submitter, "runtime": runtime}
    if family == "trace":
        submission.update(source_repository_url=source_repository, notes=notes,
                          created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                          privacy_attestation=PRIVACY_ATTESTATION)
    else:
        submission.update(source_repository=source_repository,
                          created_at=date.today().isoformat() if created_at is None else created_at,
                          known_gaps=["none-declared" if family == "defense" else "none declared"]
                          if known_gaps is None else known_gaps)
        if family in ("collective", "defense"):
            submission["deployment_class"] = deployment_class
        if family == "defense":
            submission.update(disclosure_status=disclosure_status, raw_data_shared=False)
    errors = validate_submission(submission, family=family)
    if errors:
        raise ValueError("invalid submission metadata: " + "; ".join(errors))
    if family == "trace":
        for field in ("submitter", "runtime", "source_repository_url", "notes"):
            submission[field] = submission[field].strip()
    else:
        submission["known_gaps"] = list(submission["known_gaps"])
    return submission
