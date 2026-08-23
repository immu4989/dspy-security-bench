"""Strict, data-only AcquisitionProof profiles."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
PROFILE_TYPE = "dspy-security-bench-acquisitionproof-profile"


@dataclass(frozen=True)
class AcquisitionProfile:
    raw: dict[str, Any]
    profile_sha256: str


def example_profile() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "profile_type": PROFILE_TYPE,
        "acquisition_id": "replace-with-owner-id",
        "mission": {
            "name": "Replace with bounded mission outcome",
            "description": "Describe the public or business outcome, users, and excluded uses.",
            "owner": "Replace with accountable program owner role",
        },
        "outcomes": [
            {
                "id": "safe-mission-completion",
                "metric": "summary.attack_resistance",
                "direction": "at_least",
                "target": 0.95,
                "rationale": "Replace with an owner-approved performance objective.",
            }
        ],
        "portability": {
            "data_export_required": True,
            "open_interface_required": True,
            "transition_plan_required": True,
        },
        "pricing": {
            "observation_unit": "mission-completed-within-policy",
            "required_fields": [
                "model_cost",
                "tool_cost",
                "human_review_cost",
                "failed_mission_cost",
            ],
        },
        "data_governance": {
            "flow_diagram_required": True,
            "retention_declaration_required": True,
            "training_use_declaration_required": True,
        },
        "reevaluation_triggers": [
            "model change",
            "policy or tool change",
            "material data-source change",
            "security incident",
            "owner-defined performance regression",
        ],
    }


def validate_acquisition_profile(payload: Any) -> AcquisitionProfile:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        raise ValueError("acquisition profile root must be an object")
    data = dict(payload)
    expected = {
        "schema_version",
        "profile_type",
        "acquisition_id",
        "mission",
        "outcomes",
        "portability",
        "pricing",
        "data_governance",
        "reevaluation_triggers",
    }
    if set(data) != expected:
        errors.append("profile fields are incomplete or unsupported")
    if data.get("schema_version") != 1 or data.get("profile_type") != PROFILE_TYPE:
        errors.append("profile metadata is unsupported")
    identifier = data.get("acquisition_id")
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        errors.append("acquisition_id must be a lowercase kebab-case identifier")
    _strings(data.get("mission"), ("name", "description", "owner"), "mission", errors)
    outcomes = data.get("outcomes")
    if not isinstance(outcomes, list) or not outcomes:
        errors.append("outcomes must contain at least one objective")
    else:
        ids: set[str] = set()
        for index, item in enumerate(outcomes):
            label = f"outcomes[{index}]"
            if not isinstance(item, Mapping) or set(item) != {
                "id",
                "metric",
                "direction",
                "target",
                "rationale",
            }:
                errors.append(f"{label} fields are incomplete or unsupported")
                continue
            if not isinstance(item.get("id"), str) or not _ID.fullmatch(item["id"]):
                errors.append(f"{label}.id must be kebab-case")
            elif item["id"] in ids:
                errors.append(f"{label}.id is duplicated")
            else:
                ids.add(item["id"])
            if item.get("direction") not in {"at_least", "at_most"}:
                errors.append(f"{label}.direction must be at_least or at_most")
            target = item.get("target")
            if isinstance(target, bool) or not isinstance(target, (int, float)):
                errors.append(f"{label}.target must be numeric")
            for field in ("metric", "rationale"):
                if not isinstance(item.get(field), str) or not item[field].strip():
                    errors.append(f"{label}.{field} must be non-empty")
    _booleans(
        data.get("portability"),
        ("data_export_required", "open_interface_required", "transition_plan_required"),
        "portability",
        errors,
    )
    _booleans(
        data.get("data_governance"),
        (
            "flow_diagram_required",
            "retention_declaration_required",
            "training_use_declaration_required",
        ),
        "data_governance",
        errors,
    )
    pricing = data.get("pricing")
    if not isinstance(pricing, Mapping) or set(pricing) != {"observation_unit", "required_fields"}:
        errors.append("pricing fields are incomplete or unsupported")
    else:
        if (
            not isinstance(pricing.get("observation_unit"), str)
            or not pricing["observation_unit"].strip()
        ):
            errors.append("pricing.observation_unit must be non-empty")
        required = pricing.get("required_fields")
        if (
            not isinstance(required, list)
            or not required
            or not all(isinstance(item, str) and item for item in required)
        ):
            errors.append("pricing.required_fields must contain strings")
    triggers = data.get("reevaluation_triggers")
    if (
        not isinstance(triggers, list)
        or not triggers
        or not all(isinstance(item, str) and item.strip() for item in triggers)
    ):
        errors.append("reevaluation_triggers must contain non-empty strings")
    if errors:
        raise ValueError("invalid acquisition profile: " + "; ".join(dict.fromkeys(errors)))
    return AcquisitionProfile(raw=data, profile_sha256=canonical_sha256(data))


def _strings(value: Any, fields: tuple[str, ...], label: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        errors.append(f"{label} fields are incomplete or unsupported")
        return
    for field in fields:
        if not isinstance(value.get(field), str) or not value[field].strip():
            errors.append(f"{label}.{field} must be non-empty")


def _booleans(value: Any, fields: tuple[str, ...], label: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        errors.append(f"{label} fields are incomplete or unsupported")
        return
    for field in fields:
        if not isinstance(value.get(field), bool):
            errors.append(f"{label}.{field} must be boolean")
