"""Bounded local-file ingestion for public agency AI use-case inventories."""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256

INVENTORY_SCHEMA_VERSION = 1
INVENTORY_REPORT_TYPE = "InventoryForge / Public AI use-case normalization"
MAX_INVENTORY_BYTES = 5_000_000
MAX_RECORDS = 5_000
MAX_CELL_LENGTH = 20_000
DISCLAIMER = (
    "Public-inventory normalization only. Records may be incomplete or stale. Generated "
    "MissionPacks are synthetic drafts requiring accountable human review; they are not "
    "agency-authored requirements, operational tests, procurement decisions, or endorsements."
)

_FIELD_ALIASES = {
    "use_case_id": (
        "usecaseid",
        "usecaseidentifier",
        "id",
    ),
    "name": (
        "usecasename",
        "name",
        "title",
    ),
    "agency": (
        "agency",
        "departmentagency",
        "organization",
    ),
    "bureau": (
        "bureaudepartment",
        "bureau",
        "component",
        "office",
    ),
    "summary": (
        "summaryofusecase",
        "summary",
        "description",
        "whatproblemistheaiintendedtosolve",
    ),
    "topic": (
        "usecasetopicarea",
        "topicarea",
        "topic",
        "missionarea",
    ),
    "classification": (
        "aiclassification",
        "classification",
        "typeofai",
    ),
    "stage": (
        "stageofsystemdevelopmentlifecycle",
        "stageofdevelopment",
        "stage",
        "lifecycle",
    ),
    "source_url": (
        "sourceurl",
        "publicurl",
        "url",
    ),
}
_SENSITIVE_HEADER_PARTS = ("contactname", "contactemail", "email", "phone")


@dataclass(frozen=True)
class AgencyAIUseCase:
    use_case_id: str
    name: str
    agency: str
    bureau: str
    summary: str
    topic: str
    classification: str
    stage: str
    source_url: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class AgencyAIInventory:
    source_name: str
    source_sha256: str
    records: tuple[AgencyAIUseCase, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "report_type": INVENTORY_REPORT_TYPE,
            "source_name": self.source_name,
            "source_sha256": self.source_sha256,
            "record_count": len(self.records),
            "records": [item.to_dict() for item in self.records],
            "warnings": list(self.warnings),
            "disclaimer": DISCLAIMER,
        }
        payload["report_sha256"] = canonical_sha256(payload)
        return payload


def load_public_inventory(path: str | Path) -> AgencyAIInventory:
    source = Path(path)
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read public AI inventory: {exc}") from exc
    if len(raw) > MAX_INVENTORY_BYTES:
        raise ValueError(f"inventory exceeds {MAX_INVENTORY_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("inventory must be UTF-8 text") from exc
    rows = _load_rows(text, source.suffix.lower())
    if not rows:
        raise ValueError("inventory contains no records")
    if len(rows) > MAX_RECORDS:
        raise ValueError(f"inventory cannot contain more than {MAX_RECORDS} records")
    warnings: list[str] = []
    normalized: list[AgencyAIUseCase] = []
    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        item, item_warnings = _normalize_row(row, index)
        warnings.extend(item_warnings)
        if item.use_case_id in seen:
            raise ValueError(f"duplicate use_case_id {item.use_case_id!r}")
        seen.add(item.use_case_id)
        normalized.append(item)
    return AgencyAIInventory(
        source_name=source.name,
        source_sha256=canonical_sha256(text),
        records=tuple(normalized),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def load_inventory_report(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read normalized inventory report: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("normalized inventory report must be an object")
    errors = verify_inventory_report(payload)
    if errors:
        raise ValueError("invalid normalized inventory report: " + "; ".join(errors))
    return payload


def verify_inventory_report(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    expected_fields = {
        "schema_version",
        "report_type",
        "source_name",
        "source_sha256",
        "record_count",
        "records",
        "warnings",
        "disclaimer",
        "report_sha256",
    }
    if set(payload) != expected_fields:
        errors.append("inventory report fields are incomplete or unsupported")
    if payload.get("schema_version") != INVENTORY_SCHEMA_VERSION:
        errors.append("unsupported schema_version")
    if payload.get("report_type") != INVENTORY_REPORT_TYPE:
        errors.append("unsupported report_type")
    if payload.get("disclaimer") != DISCLAIMER:
        errors.append("disclaimer does not match InventoryForge v1")
    for field in ("source_name", "source_sha256"):
        if not isinstance(payload.get(field), str) or not payload.get(field):
            errors.append(f"{field} must be a non-empty string")
    if not _digest(payload.get("source_sha256")):
        errors.append("source_sha256 must be a lowercase SHA-256 digest")
    warnings = payload.get("warnings")
    if not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings):
        errors.append("warnings must be a list of strings")
    records = payload.get("records")
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_RECORDS:
        errors.append(f"records must contain 1 to {MAX_RECORDS} entries")
        records = []
    if payload.get("record_count") != len(records):
        errors.append("record_count does not recompute")
    ids: set[str] = set()
    fields = set(AgencyAIUseCase.__dataclass_fields__)
    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping) or set(record) != fields:
            errors.append(f"record {index} fields are incomplete or unsupported")
            continue
        for field in fields:
            value = record.get(field)
            if not isinstance(value, str) or len(value) > MAX_CELL_LENGTH:
                errors.append(f"record {index} {field} must be a bounded string")
        identifier = record.get("use_case_id")
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"record {index} use_case_id must be non-empty")
        elif identifier in ids:
            errors.append(f"record {index} use_case_id is duplicated")
        else:
            ids.add(identifier)
    unsigned = dict(payload)
    claimed = unsigned.pop("report_sha256", None)
    try:
        actual = canonical_sha256(unsigned)
    except (TypeError, ValueError):
        actual = None
        errors.append("inventory report is not canonical JSON data")
    if claimed != actual:
        errors.append("report_sha256 does not match canonical report content")
    return tuple(dict.fromkeys(errors))


def find_use_case(payload: Mapping[str, Any], use_case_id: str) -> AgencyAIUseCase:
    records = payload.get("records")
    if not isinstance(records, list):
        raise ValueError("inventory report contains no records")
    matches = [item for item in records if item.get("use_case_id") == use_case_id]
    if len(matches) != 1:
        raise ValueError(f"use_case_id {use_case_id!r} was not found exactly once")
    return AgencyAIUseCase(**matches[0])


def _load_rows(text: str, suffix: str) -> list[dict[str, Any]]:
    if suffix == ".csv":
        try:
            return [dict(row) for row in csv.DictReader(io.StringIO(text))]
        except csv.Error as exc:
            raise ValueError(f"invalid inventory CSV: {exc}") from exc
    if suffix == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid inventory JSON: {exc}") from exc
        if isinstance(payload, Mapping):
            payload = payload.get("records", payload.get("data"))
        if not isinstance(payload, list) or not all(isinstance(item, Mapping) for item in payload):
            raise ValueError("inventory JSON must be a list of objects or contain records/data")
        return [dict(item) for item in payload]
    raise ValueError("inventory must use .csv or .json")


def _normalize_row(row: Mapping[str, Any], index: int) -> tuple[AgencyAIUseCase, list[str]]:
    normalized_headers = {_header(key): key for key in row}
    warnings = []
    ignored = sorted(
        key for key in normalized_headers if any(part in key for part in _SENSITIVE_HEADER_PARTS)
    )
    if ignored:
        warnings.append("contact fields were ignored and are never preserved")
    values: dict[str, str] = {}
    for field, aliases in _FIELD_ALIASES.items():
        original = next(
            (normalized_headers[alias] for alias in aliases if alias in normalized_headers), None
        )
        raw = row.get(original, "") if original is not None else ""
        value = "" if raw is None else str(raw).strip()
        if len(value) > MAX_CELL_LENGTH:
            raise ValueError(f"record {index} field {field} exceeds {MAX_CELL_LENGTH} characters")
        values[field] = value
    if not values["use_case_id"]:
        values["use_case_id"] = f"record-{index}"
        warnings.append("missing use-case IDs were replaced with deterministic record IDs")
    if not values["name"]:
        raise ValueError(f"record {index} has no recognizable use-case name")
    if not values["summary"]:
        raise ValueError(f"record {index} has no recognizable use-case summary")
    if not values["agency"]:
        values["agency"] = "unspecified-public-organization"
        warnings.append("missing agency values were labeled unspecified")
    return AgencyAIUseCase(**values), warnings


def _header(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _digest(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))
