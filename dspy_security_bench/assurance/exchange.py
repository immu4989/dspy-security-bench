"""Strict, non-ranking metadata registry for public AssuranceGraph reproductions."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from dspy_security_bench.assurance.case import CLAIM_STATUSES
from dspy_security_bench.assurance.profiles import built_in_profile, profile_ids
from dspy_security_bench.mission.loader import canonical_sha256

REGISTRY_TYPE = "dspy-security-bench-assurance-exchange"
REGISTRY_VERSION = 1
CLAIM_BOUNDARY = (
    "The exchange is a metadata index for independently reproducible, safely public "
    "AssuranceGraph reports. Admission validates declared structure and content identity; it "
    "does not authenticate observations, rank systems, certify safety or compliance, authorize "
    "operation, approve procurement, accept risk, or imply government endorsement."
)
SECTORS = (
    "cross-sector",
    "emergency-logistics",
    "financial-investigation",
    "healthcare-administration",
    "manufacturing-maintenance",
    "public-benefits",
    "software-development",
    "water-operations",
)
EVIDENCE_KINDS = (
    "authority",
    "collective-v2",
    "containment",
    "defense-portfolio",
    "dependency-impact",
    "schedule",
    "trace",
    "verified-defense",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{7,64}\Z")
_REGISTRY_FIELDS = {
    "schema_version",
    "registry_type",
    "entries",
    "ranking_enabled",
    "automatic_endorsements",
    "claim_boundary",
    "registry_sha256",
}
_ENTRY_FIELDS = {
    "case_id",
    "profile_id",
    "sector",
    "report_sha256",
    "case_sha256",
    "source_repository",
    "source_revision",
    "report_url",
    "submitted_by",
    "disclosure",
    "status",
    "claim_outcomes",
    "evidence_kinds",
    "independent_reproductions",
    "updated_at",
    "known_gaps",
}
_REPRODUCTION_FIELDS = {
    "reproduced_by",
    "report_sha256",
    "source_repository",
    "source_revision",
    "reproduced_at",
    "known_gap",
}


def empty_exchange() -> dict[str, Any]:
    return seal_exchange(
        {
            "schema_version": REGISTRY_VERSION,
            "registry_type": REGISTRY_TYPE,
            "entries": [],
            "ranking_enabled": False,
            "automatic_endorsements": 0,
            "claim_boundary": CLAIM_BOUNDARY,
        }
    )


def seal_exchange(exchange: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _clone(exchange)
    normalized.pop("registry_sha256", None)
    normalized["registry_sha256"] = canonical_sha256(normalized)
    return normalized


def validate_exchange(exchange: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(exchange, Mapping):
        return ("exchange must be an object",)
    _exact_keys(exchange, _REGISTRY_FIELDS, "exchange", errors)
    if (
        exchange.get("schema_version") != REGISTRY_VERSION
        or exchange.get("registry_type") != REGISTRY_TYPE
    ):
        errors.append("exchange metadata does not match assurance exchange v1")
    if exchange.get("ranking_enabled") is not False:
        errors.append("ranking_enabled must be false")
    if exchange.get("automatic_endorsements") != 0:
        errors.append("automatic_endorsements must be zero")
    if exchange.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match assurance exchange v1")
    entries = exchange.get("entries")
    if not isinstance(entries, list) or len(entries) > 10_000:
        errors.append("entries must be a list of at most 10000 objects")
        entries = []
    identities: set[tuple[Any, Any]] = set()
    for index, entry in enumerate(entries):
        label = f"entries[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact_keys(entry, _ENTRY_FIELDS, label, errors)
        _identifier(entry.get("case_id"), f"{label}.case_id", errors)
        if entry.get("profile_id") not in profile_ids():
            errors.append(f"{label}.profile_id is not a frozen profile")
            required_kinds = None
            claim_count = None
        else:
            profile = built_in_profile(entry["profile_id"])
            required_kinds = {claim["evidence_kind"] for claim in profile["claims"]}
            claim_count = len(profile["claims"])
        if entry.get("sector") not in SECTORS:
            errors.append(f"{label}.sector is unsupported")
        for field in ("report_sha256", "case_sha256"):
            if not isinstance(entry.get(field), str) or not _DIGEST.fullmatch(entry[field]):
                errors.append(f"{label}.{field} must be a SHA-256 digest")
        _https_url(entry.get("source_repository"), f"{label}.source_repository", errors)
        revision = entry.get("source_revision")
        if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
            errors.append(f"{label}.source_revision must be a 7-64 character hex revision")
        _https_url(entry.get("report_url"), f"{label}.report_url", errors)
        _string(entry.get("submitted_by"), f"{label}.submitted_by", 200, errors)
        if entry.get("disclosure") not in {"synthetic", "sanitized-public"}:
            errors.append(f"{label}.disclosure is unsupported")
        if entry.get("status") not in {"active", "stale", "withdrawn", "superseded"}:
            errors.append(f"{label}.status is unsupported")
        outcomes = entry.get("claim_outcomes")
        if not isinstance(outcomes, Mapping) or set(outcomes) != set(CLAIM_STATUSES):
            errors.append(f"{label}.claim_outcomes must contain every frozen status")
        elif any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in outcomes.values()
        ):
            errors.append(f"{label}.claim_outcomes values must be non-negative integers")
        elif claim_count is not None and sum(outcomes.values()) != claim_count:
            errors.append(f"{label}.claim_outcomes must sum to the selected profile claim count")
        kinds = entry.get("evidence_kinds")
        if (
            not isinstance(kinds, list)
            or not kinds
            or len(kinds) != len(set(kinds))
            or any(kind not in EVIDENCE_KINDS for kind in kinds)
        ):
            errors.append(f"{label}.evidence_kinds must be a unique non-empty supported list")
        elif required_kinds is not None and set(kinds) != required_kinds:
            errors.append(f"{label}.evidence_kinds must match the selected profile")
        reproductions = entry.get("independent_reproductions")
        if not isinstance(reproductions, list) or len(reproductions) > 1_000:
            errors.append(f"{label}.independent_reproductions must be a list of at most 1000")
            reproductions = []
        reproduction_identities: set[tuple[Any, Any]] = set()
        for reproduction_index, reproduction in enumerate(reproductions):
            reproduction_label = f"{label}.independent_reproductions[{reproduction_index}]"
            if not isinstance(reproduction, Mapping):
                errors.append(f"{reproduction_label} must be an object")
                continue
            _exact_keys(reproduction, _REPRODUCTION_FIELDS, reproduction_label, errors)
            _string(
                reproduction.get("reproduced_by"),
                f"{reproduction_label}.reproduced_by",
                200,
                errors,
            )
            if reproduction.get("report_sha256") != entry.get("report_sha256"):
                errors.append(f"{reproduction_label}.report_sha256 must match the indexed report")
            _https_url(
                reproduction.get("source_repository"),
                f"{reproduction_label}.source_repository",
                errors,
            )
            reproduction_revision = reproduction.get("source_revision")
            if not isinstance(reproduction_revision, str) or not _REVISION.fullmatch(
                reproduction_revision
            ):
                errors.append(
                    f"{reproduction_label}.source_revision must be a 7-64 character hex revision"
                )
            reproduced_at = reproduction.get("reproduced_at")
            if (
                isinstance(reproduced_at, bool)
                or not isinstance(reproduced_at, int)
                or reproduced_at < 0
            ):
                errors.append(f"{reproduction_label}.reproduced_at must be a Unix timestamp")
            _string(
                reproduction.get("known_gap"),
                f"{reproduction_label}.known_gap",
                500,
                errors,
            )
            reproduction_identity = (
                reproduction.get("reproduced_by"),
                reproduction.get("source_revision"),
            )
            if reproduction_identity in reproduction_identities:
                errors.append(f"{reproduction_label} duplicates a reproducer/revision identity")
            reproduction_identities.add(reproduction_identity)
        updated_at = entry.get("updated_at")
        if isinstance(updated_at, bool) or not isinstance(updated_at, int) or updated_at < 0:
            errors.append(f"{label}.updated_at must be a non-negative Unix timestamp")
        gaps = entry.get("known_gaps")
        if (
            not isinstance(gaps, list)
            or not gaps
            or len(gaps) > 100
            or any(
                not isinstance(item, str) or not item.strip() or len(item) > 500 for item in gaps
            )
        ):
            errors.append(f"{label}.known_gaps must contain 1-100 bounded strings")
        identity = (entry.get("case_id"), entry.get("report_sha256"))
        if identity in identities:
            errors.append(f"{label} duplicates a case/report identity")
        identities.add(identity)
    claimed = exchange.get("registry_sha256")
    unsigned = dict(exchange)
    unsigned.pop("registry_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("registry_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("exchange is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def load_exchange(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if source.stat().st_size > 10_000_000:
        raise ValueError("exchange exceeds 10000000 bytes")
    payload = json.loads(source.read_text())
    if not isinstance(payload, dict):
        raise ValueError("exchange JSON root must be an object")
    errors = validate_exchange(payload)
    if errors:
        raise ValueError("invalid assurance exchange: " + "; ".join(errors))
    return payload


def exchange_summary(exchange: Mapping[str, Any]) -> dict[str, Any]:
    errors = validate_exchange(exchange)
    if errors:
        raise ValueError("invalid assurance exchange: " + "; ".join(errors))
    active = [item for item in exchange["entries"] if item["status"] == "active"]
    return {
        "entryCount": len(exchange["entries"]),
        "activeEntryCount": len(active),
        "independentReproductionCount": sum(
            len(item["independent_reproductions"]) for item in active
        ),
        "sectorCount": len({item["sector"] for item in active}),
        "rankingEnabled": False,
        "automaticEndorsements": 0,
    }


def _https_url(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or len(value) > 2_000:
        errors.append(f"{label} must be a bounded HTTPS URL")
        return
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.netloc
        or parts.username
        or parts.password
        or parts.fragment
    ):
        errors.append(f"{label} must be a public HTTPS URL without credentials or fragments")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _string(value: Any, label: str, maximum: int, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        errors.append(f"{label} must be a non-empty string of at most {maximum} characters")


def _exact_keys(
    value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]
) -> None:
    missing, extra = sorted(expected - set(value)), sorted(set(value) - expected)
    if missing:
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra:
        errors.append(f"{label} has unsupported fields: {', '.join(extra)}")


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
