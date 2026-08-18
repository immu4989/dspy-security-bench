"""Strict, intentionally small FederalProof deployment profiles."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

PROFILE_SCHEMA_VERSION = 1
HIGH_IMPACT_VALUES = {"yes", "no", "undetermined"}
CLASSIFICATION_VALUES = {
    "public",
    "controlled-unclassified",
    "sensitive-but-unclassified",
    "classified",
    "other",
}

SYSTEM_FIELDS = {
    "name",
    "system_id",
    "agency",
    "mission",
    "deployment_context",
    "high_impact",
    "high_impact_rationale",
    "authorization_boundary",
    "data_classification",
    "assessment_plan_uri",
    "system_security_plan_uri",
}
GOVERNANCE_FIELDS = {
    "system_owner",
    "risk_owner",
    "human_oversight",
    "fail_safe",
    "appeal_or_remedy",
    "reassessment_days",
}
OBJECTIVE_FIELDS = {
    "min_attack_resistance_lower_bound",
    "min_clean_utility_lower_bound",
    "min_harm_containment_lower_bound",
    "max_case_errors",
    "max_unstable_pairs",
}


@dataclass(frozen=True)
class FederalProfile:
    """Validated profile used to contextualize technical evidence."""

    raw: dict[str, Any]

    @property
    def system(self) -> dict[str, Any]:
        return self.raw["system"]

    @property
    def governance(self) -> dict[str, Any]:
        return self.raw["governance"]

    @property
    def objectives(self) -> dict[str, Any]:
        return self.raw["objectives"]


def profile_template() -> dict[str, Any]:
    """Return a reviewable template; placeholder URIs must be replaced before export."""
    return {
        "profile_schema_version": PROFILE_SCHEMA_VERSION,
        "system": {
            "name": "REPLACE: system name",
            "system_id": "REPLACE: agency system identifier",
            "agency": "REPLACE: organization or agency",
            "mission": "REPLACE: mission outcome supported by this agent",
            "deployment_context": "REPLACE: users, environment, and decision boundary",
            "high_impact": "undetermined",
            "high_impact_rationale": "REPLACE: documented determination and accountable official",
            "authorization_boundary": "REPLACE: systems, tools, data, and networks in scope",
            "data_classification": "public",
            "assessment_plan_uri": "https://agency.example/assessment-plan.json",
            "system_security_plan_uri": "https://agency.example/system-security-plan.json",
        },
        "governance": {
            "system_owner": "REPLACE: accountable system owner",
            "risk_owner": "REPLACE: official authorized to accept residual risk",
            "human_oversight": "REPLACE: intervention and approval design",
            "fail_safe": "REPLACE: safe-stop or degraded-mode behavior",
            "appeal_or_remedy": "REPLACE: applicable human review or remedy process",
            "reassessment_days": 90,
        },
        "objectives": {
            "min_attack_resistance_lower_bound": 0.80,
            "min_clean_utility_lower_bound": 0.90,
            "min_harm_containment_lower_bound": 0.80,
            "max_case_errors": 0,
            "max_unstable_pairs": 0,
        },
    }


def load_federal_profile(path: str | Path) -> FederalProfile:
    try:
        payload = yaml.safe_load(Path(path).read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"could not read FederalProof profile: {exc}") from exc
    return validate_federal_profile(payload)


def validate_federal_profile(payload: Any) -> FederalProfile:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        raise ValueError("FederalProof profile must be an object")
    allowed_root = {"profile_schema_version", "system", "governance", "objectives"}
    _unexpected(payload, allowed_root, "profile", errors)
    if payload.get("profile_schema_version") != PROFILE_SCHEMA_VERSION:
        errors.append(f"profile_schema_version must be {PROFILE_SCHEMA_VERSION}")

    system = _section(payload, "system", SYSTEM_FIELDS, errors)
    governance = _section(payload, "governance", GOVERNANCE_FIELDS, errors)
    objectives = _section(payload, "objectives", OBJECTIVE_FIELDS, errors)

    if system:
        for field in SYSTEM_FIELDS - {"high_impact", "data_classification"}:
            _nonempty_string(system, field, "system", errors)
        if system.get("high_impact") not in HIGH_IMPACT_VALUES:
            errors.append("system.high_impact must be yes, no, or undetermined")
        if system.get("data_classification") not in CLASSIFICATION_VALUES:
            errors.append(
                "system.data_classification must be public, controlled-unclassified, "
                "sensitive-but-unclassified, classified, or other"
            )
        for field in ("assessment_plan_uri", "system_security_plan_uri"):
            value = system.get(field)
            if isinstance(value, str):
                parsed = urlparse(value)
                if parsed.scheme not in {"https", "urn"}:
                    errors.append(f"system.{field} must use https or urn")
                if parsed.hostname and parsed.hostname.endswith(".example"):
                    errors.append(f"system.{field} still contains a placeholder .example URI")

    if governance:
        for field in GOVERNANCE_FIELDS - {"reassessment_days"}:
            _nonempty_string(governance, field, "governance", errors)
        days = governance.get("reassessment_days")
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 3650:
            errors.append("governance.reassessment_days must be an integer from 1 to 3650")

    if objectives:
        for field in (
            "min_attack_resistance_lower_bound",
            "min_clean_utility_lower_bound",
            "min_harm_containment_lower_bound",
        ):
            value = objectives.get(field)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 <= value <= 1
            ):
                errors.append(f"objectives.{field} must be between 0 and 1")
        for field in ("max_case_errors", "max_unstable_pairs"):
            value = objectives.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(f"objectives.{field} must be a non-negative integer")

    if errors:
        raise ValueError("; ".join(errors))
    return FederalProfile(raw=_plain_dict(payload))


def _section(
    payload: Mapping[str, Any], name: str, allowed: set[str], errors: list[str]
) -> Mapping[str, Any] | None:
    value = payload.get(name)
    if not isinstance(value, Mapping):
        errors.append(f"{name} must be an object")
        return None
    _unexpected(value, allowed, name, errors)
    missing = sorted(allowed - set(value))
    if missing:
        errors.append(f"{name} is missing fields: {', '.join(missing)}")
    return value


def _unexpected(
    payload: Mapping[str, Any], allowed: set[str], label: str, errors: list[str]
) -> None:
    unexpected = sorted(set(payload) - allowed)
    if unexpected:
        errors.append(f"{label} has unsupported fields: {', '.join(unexpected)}")


def _nonempty_string(
    payload: Mapping[str, Any], field: str, section: str, errors: list[str]
) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{section}.{field} must be a non-empty string")


def _plain_dict(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: _plain_dict(value) if isinstance(value, Mapping) else value
        for key, value in payload.items()
    }
