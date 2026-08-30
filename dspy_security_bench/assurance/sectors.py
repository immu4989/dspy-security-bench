"""Fictional, editable sector starters for AssuranceGraph adoption.

These are boundary templates, not claims about a real organization or system.
They deliberately contain placeholder owners and zero evidence digests so they
cannot be mistaken for completed assurance cases.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from dspy_security_bench.assurance.case import built_in_case, seal_case

SECTOR_BOUNDARY = (
    "This fictional starter describes an editable assurance boundary only. It contains no "
    "operational data, production endpoint, agency determination, sector certification, "
    "authorization to operate, deployment approval, or government endorsement."
)

_SECTORS: dict[str, dict[str, str]] = {
    "emergency-logistics": {
        "title": "Emergency logistics coordination assistant",
        "profile_id": "federal-high-impact",
        "system_name": "Fictional emergency logistics assistant",
        "mission": "Prioritize synthetic supply requests while a human logistics officer approves every external effect.",
        "environment": "isolated exercise environment with synthetic incident and inventory records",
        "boundary": "Decision support ends before dispatch, resource allocation, public communication, or responder tasking.",
    },
    "financial-investigation": {
        "title": "Financial investigation research assistant",
        "profile_id": "federal-high-impact",
        "system_name": "Fictional financial investigation assistant",
        "mission": "Correlate synthetic filings and produce cited leads for human investigator review.",
        "environment": "segmented analytic enclave containing synthetic financial records",
        "boundary": "No account action, transaction hold, referral, allegation, identity decision, or external disclosure is permitted.",
    },
    "healthcare-administration": {
        "title": "Healthcare administration support agent",
        "profile_id": "enterprise-agent",
        "system_name": "Fictional healthcare administration assistant",
        "mission": "Draft scheduling and benefits-administration recommendations from synthetic records for staff review.",
        "environment": "non-clinical test environment with synthetic patient and plan data",
        "boundary": "No diagnosis, treatment, eligibility determination, claim denial, patient contact, or production record write is permitted.",
    },
    "manufacturing-maintenance": {
        "title": "Manufacturing maintenance planning agent",
        "profile_id": "critical-infrastructure",
        "system_name": "Fictional manufacturing maintenance assistant",
        "mission": "Rank synthetic maintenance work orders while operators retain equipment-control authority.",
        "environment": "offline digital twin with synthetic asset telemetry",
        "boundary": "No programmable controller access, safety-instrumented-system change, work-order dispatch, or production actuation is permitted.",
    },
    "public-benefits": {
        "title": "Public benefits caseworker assistant",
        "profile_id": "federal-high-impact",
        "system_name": "Fictional public benefits assistant",
        "mission": "Summarize synthetic case records and cite policy for accountable caseworker review.",
        "environment": "isolated pre-production environment with synthetic applicant records",
        "boundary": "No eligibility decision, benefit change, adverse action, applicant communication, or production case write is permitted.",
    },
    "software-development": {
        "title": "Software development and security assistant",
        "profile_id": "enterprise-agent",
        "system_name": "Fictional software engineering assistant",
        "mission": "Analyze a synthetic repository and propose reviewable code changes without release authority.",
        "environment": "ephemeral sandbox with a synthetic repository and deny-by-default egress",
        "boundary": "No secret access, production deployment, branch protection change, package publication, or external issue creation is permitted.",
    },
    "water-operations": {
        "title": "Water operations decision-support agent",
        "profile_id": "critical-infrastructure",
        "system_name": "Fictional water operations assistant",
        "mission": "Analyze synthetic alarms and propose operator-reviewed continuity actions.",
        "environment": "disconnected water-system digital twin with synthetic telemetry",
        "boundary": "No operational-technology connection, setpoint change, chemical-dose recommendation execution, alarm suppression, or public notice is permitted.",
    },
}


def sector_ids() -> tuple[str, ...]:
    """Return stable identifiers for every reference sector."""

    return tuple(sorted(_SECTORS))


def sector_profile(sector_id: str) -> dict[str, str]:
    """Return an immutable-by-copy description of one fictional sector starter."""

    try:
        result = deepcopy(_SECTORS[sector_id])
    except KeyError as exc:
        raise ValueError(f"unknown AssuranceGraph sector {sector_id!r}") from exc
    return {"sector_id": sector_id, **result, "claim_boundary": SECTOR_BOUNDARY}


def sector_case(
    sector_id: str,
    *,
    case_id: str | None = None,
    evaluation_time: int = 1_788_048_000,
) -> dict[str, Any]:
    """Build a sealed, intentionally incomplete AssuranceGraph sector starter."""

    sector = sector_profile(sector_id)
    payload = built_in_case(
        sector["profile_id"],
        case_id=case_id or f"{sector_id}-assurance",
        evaluation_time=evaluation_time,
    )
    payload["title"] = sector["title"]
    payload["description"] = (
        f"Editable fictional {sector_id} reference case. {SECTOR_BOUNDARY} Replace every "
        "owner, timestamp, path, digest, system field, and profile choice before evaluation."
    )
    payload["decision_owner"] = "replace-with-accountable-mission-owner"
    payload["system"] = {
        "system_id": f"fictional-{sector_id}-agent",
        "name": sector["system_name"],
        "mission": sector["mission"],
        "environment": sector["environment"],
        "boundary": sector["boundary"],
    }
    return seal_case(payload)
