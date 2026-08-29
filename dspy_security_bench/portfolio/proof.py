"""ResilienceGraph: exact planning over verified cyber-defense evidence.

The planner deliberately solves a small, declared decision problem exactly. It
does not predict incidents, monetize harm, rank vendors, or touch a live system.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from dspy_security_bench.defend.protocol import (
    analyze_remediation,
    built_in_mission,
    built_in_proposal,
)
from dspy_security_bench.defend.protocol import (
    verify_report as verify_defender_report,
)
from dspy_security_bench.mission.loader import canonical_sha256

CAMPAIGN_TYPE = "dspy-security-bench-resilience-campaign"
REPORT_TYPE = "ResilienceGraph / Verified defense portfolio evidence"
PROTOCOL_VERSION = "resiliencegraph-v1"
ANALYZER = "exact-resilience-frontier-v1"
MAX_ACTIONS = 18
MAX_CAMPAIGN_BYTES = 5_000_000
CLAIM_BOUNDARY = (
    "ResilienceGraph performs exact arithmetic over owner-supplied planning metadata and "
    "locally recomputable DefenderTwin reports. Dependency reach is a structural planning "
    "signal, not proof that a downstream service is secure. The output is not a forecast, "
    "risk assessment, benefit-cost analysis, funding recommendation, vendor ranking, control "
    "assessment, authorization to operate, or government endorsement. Accountable owners "
    "retain every prioritization, funding, deployment, and risk-acceptance decision."
)
LIMITATIONS = (
    "Only declared services, dependencies, candidates, resource units, groups, and scenarios are analyzed.",
    "DefenderTwin evidence is synthetic and does not establish production exploitability or deployment behavior.",
    "Scenario availability and service mappings are owner-supplied assumptions, not verified facts.",
    "Ordinal resource units and criticality weights are not dollars, probabilities, avoided losses, or economic forecasts.",
    "The displayed frontier is complete only while the campaign stays within the frozen 18-action bound.",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_CAMPAIGN_FIELDS = {
    "schema_version",
    "campaign_type",
    "campaign_id",
    "name",
    "decision_owner",
    "decision_context",
    "services",
    "actions",
    "scenarios",
    "constraints",
    "claim_boundary",
    "campaign_sha256",
}
_SERVICE_FIELDS = {
    "service_id",
    "name",
    "sector",
    "community",
    "criticality_weight",
    "depends_on",
}
_ACTION_FIELDS = {
    "action_id",
    "name",
    "supplier_id",
    "planning_service_ids",
    "beneficiary_groups",
    "resource_demand",
    "prerequisite_action_ids",
    "exclusive_with_action_ids",
    "defender_report",
}
_RESOURCE_FIELDS = {"budget_units", "workforce_units", "disruption_units"}
_SCENARIO_FIELDS = {"scenario_id", "name", "unavailable_action_ids"}
_CONSTRAINT_FIELDS = {
    "max_budget_units",
    "max_workforce_units",
    "max_disruption_units",
    "max_actions",
    "max_actions_per_supplier",
    "required_service_ids",
    "required_beneficiary_groups",
}


def protocol_payload() -> dict[str, Any]:
    """Return the frozen, content-addressed ResilienceGraph measurement contract."""

    return {
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "maximum_actions": MAX_ACTIONS,
        "source_evidence": "valid DefenderTwin report with effective_and_safe outcome",
        "enumeration": "all subsets of eligible actions",
        "feasibility": [
            "owner resource ceilings",
            "action prerequisites and exclusions",
            "supplier concentration ceiling",
            "required direct-service and beneficiary-group floors",
        ],
        "scenario_model": "owner-declared unavailable actions; no probabilities inferred",
        "frontier_objectives": {
            "maximize": [
                "scenarios meeting declared floors",
                "worst-case direct critical-service weight",
                "worst-case downstream dependency-reach weight",
                "worst-case beneficiary-group count",
            ],
            "minimize": [
                "budget units",
                "workforce units",
                "disruption units",
                "action count",
            ],
        },
        "tie_break": "lexicographic reference selection; explicitly not a recommendation",
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }


def protocol_sha256() -> str:
    return canonical_sha256(protocol_payload())


def seal_campaign(campaign: Mapping[str, Any]) -> dict[str, Any]:
    """Return a JSON-normalized campaign with a recomputed digest."""

    normalized = _json_clone(campaign)
    normalized.pop("campaign_sha256", None)
    normalized["campaign_sha256"] = canonical_sha256(normalized)
    return normalized


def built_in_campaign() -> dict[str, Any]:
    """Build a fictional cross-sector campaign, including one unsafe candidate."""

    reports = {
        name: analyze_remediation(built_in_mission(name), built_in_proposal(built_in_mission(name)))
        for name in (
            "community-hospital",
            "water-utility",
            "local-government",
            "open-source-maintainer",
            "small-business",
        )
    }
    unsafe_mission = built_in_mission("community-hospital")
    unsafe_report = analyze_remediation(
        unsafe_mission, built_in_proposal(unsafe_mission, "disruptive-reference")
    )

    def action(
        action_id: str,
        name: str,
        supplier_id: str,
        service_id: str,
        groups: list[str],
        demand: tuple[int, int, int],
        report: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "action_id": action_id,
            "name": name,
            "supplier_id": supplier_id,
            "planning_service_ids": [service_id],
            "beneficiary_groups": groups,
            "resource_demand": {
                "budget_units": demand[0],
                "workforce_units": demand[1],
                "disruption_units": demand[2],
            },
            "prerequisite_action_ids": [],
            "exclusive_with_action_ids": [],
            "defender_report": dict(report),
        }

    payload: dict[str, Any] = {
        "schema_version": 1,
        "campaign_type": CAMPAIGN_TYPE,
        "campaign_id": "fictional-regional-resilience",
        "name": "Fictional regional essential-service defense portfolio",
        "decision_owner": "accountable cross-sector planning group",
        "decision_context": (
            "Compare bounded, synthetic remediation portfolios under shared resource and "
            "provider-availability constraints. Replace every planning assumption locally."
        ),
        "services": [
            {
                "service_id": "software-supply",
                "name": "Open software supply",
                "sector": "information-technology",
                "community": "regional",
                "criticality_weight": 4,
                "depends_on": [],
            },
            {
                "service_id": "digital-communications",
                "name": "Digital communications",
                "sector": "communications",
                "community": "regional",
                "criticality_weight": 5,
                "depends_on": ["software-supply"],
            },
            {
                "service_id": "clinical-care",
                "name": "Clinical care coordination",
                "sector": "healthcare",
                "community": "regional",
                "criticality_weight": 5,
                "depends_on": ["digital-communications"],
            },
            {
                "service_id": "water-operations",
                "name": "Water service operations",
                "sector": "water",
                "community": "regional",
                "criticality_weight": 5,
                "depends_on": ["digital-communications"],
            },
            {
                "service_id": "resident-services",
                "name": "Resident-facing government services",
                "sector": "government-services",
                "community": "regional",
                "criticality_weight": 4,
                "depends_on": ["digital-communications"],
            },
            {
                "service_id": "small-commerce",
                "name": "Small-business digital commerce",
                "sector": "commercial-facilities",
                "community": "regional",
                "criticality_weight": 3,
                "depends_on": ["digital-communications"],
            },
        ],
        "actions": [
            action(
                "hospital-bounded-fix",
                "Bounded hospital remediation",
                "shared-provider-a",
                "clinical-care",
                ["healthcare", "public-health"],
                (5, 3, 2),
                reports["community-hospital"],
            ),
            action(
                "water-bounded-fix",
                "Bounded water-utility remediation",
                "water-specialist",
                "water-operations",
                ["public-sector", "rural-community"],
                (4, 3, 1),
                reports["water-utility"],
            ),
            action(
                "government-bounded-fix",
                "Bounded local-government remediation",
                "civic-security-cooperative",
                "resident-services",
                ["public-sector", "underserved-community"],
                (3, 2, 1),
                reports["local-government"],
            ),
            action(
                "open-source-bounded-fix",
                "Bounded open-source remediation",
                "maintainer-cooperative",
                "software-supply",
                ["open-source", "small-organizations"],
                (2, 1, 1),
                reports["open-source-maintainer"],
            ),
            action(
                "small-business-bounded-fix",
                "Bounded small-business remediation",
                "shared-provider-a",
                "small-commerce",
                ["small-business", "small-organizations"],
                (2, 1, 1),
                reports["small-business"],
            ),
            action(
                "hospital-disruptive-fix",
                "Disruptive hospital option (expected exclusion)",
                "shared-provider-b",
                "clinical-care",
                ["healthcare", "public-health"],
                (1, 1, 5),
                unsafe_report,
            ),
        ],
        "scenarios": [
            {
                "scenario_id": "baseline",
                "name": "All candidates available",
                "unavailable_action_ids": [],
            },
            {
                "scenario_id": "shared-provider-loss",
                "name": "Shared provider A unavailable",
                "unavailable_action_ids": [
                    "hospital-bounded-fix",
                    "small-business-bounded-fix",
                ],
            },
            {
                "scenario_id": "maintainer-capacity-loss",
                "name": "Open-source maintainer capacity unavailable",
                "unavailable_action_ids": ["open-source-bounded-fix"],
            },
        ],
        "constraints": {
            "max_budget_units": 11,
            "max_workforce_units": 7,
            "max_disruption_units": 5,
            "max_actions": 4,
            "max_actions_per_supplier": 2,
            "required_service_ids": [],
            "required_beneficiary_groups": ["public-sector", "small-organizations"],
        },
        "claim_boundary": CLAIM_BOUNDARY,
    }
    return seal_campaign(payload)


def validate_campaign(campaign: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate a bounded campaign and every embedded DefenderTwin report."""

    errors: list[str] = []
    if not isinstance(campaign, Mapping):
        return ("campaign must be an object",)
    try:
        normalized = _json_clone(campaign)
        size = len(json.dumps(normalized, ensure_ascii=False, allow_nan=False).encode())
    except (TypeError, ValueError) as exc:
        return (f"campaign must contain finite JSON values: {exc}",)
    if size > MAX_CAMPAIGN_BYTES:
        errors.append(f"campaign exceeds {MAX_CAMPAIGN_BYTES} bytes")
    if set(normalized) != _CAMPAIGN_FIELDS:
        errors.append("campaign fields are incomplete or unsupported")
    if normalized.get("schema_version") != 1 or normalized.get("campaign_type") != CAMPAIGN_TYPE:
        errors.append("unsupported campaign schema or type")
    for field in ("campaign_id", "name", "decision_owner", "decision_context"):
        _check_text(normalized.get(field), f"campaign {field}", errors)
    _check_id(normalized.get("campaign_id"), "campaign campaign_id", errors)
    if normalized.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("campaign claim_boundary does not match the frozen protocol")
    unsigned = dict(normalized)
    claimed = unsigned.pop("campaign_sha256", None)
    if not _sha256(claimed) or claimed != canonical_sha256(unsigned):
        errors.append("campaign_sha256 does not recompute")

    services = normalized.get("services")
    service_ids: set[str] = set()
    dependencies: dict[str, list[str]] = {}
    if not isinstance(services, list) or not 1 <= len(services) <= 50:
        errors.append("campaign services must contain 1..50 entries")
        services = []
    for index, service in enumerate(services):
        label = f"service[{index}]"
        if not isinstance(service, dict) or set(service) != _SERVICE_FIELDS:
            errors.append(f"{label} fields are incomplete or unsupported")
            continue
        service_id = service.get("service_id")
        _check_id(service_id, f"{label} service_id", errors)
        if service_id in service_ids:
            errors.append(f"duplicate service_id {service_id!r}")
        if isinstance(service_id, str):
            service_ids.add(service_id)
        for field in ("name", "sector", "community"):
            _check_text(service.get(field), f"{label} {field}", errors)
        _check_id(service.get("sector"), f"{label} sector", errors)
        _check_id(service.get("community"), f"{label} community", errors)
        weight = service.get("criticality_weight")
        if isinstance(weight, bool) or not isinstance(weight, int) or not 1 <= weight <= 5:
            errors.append(f"{label} criticality_weight must be an integer from 1 to 5")
        deps = service.get("depends_on")
        if not _id_list(deps, maximum=20):
            errors.append(f"{label} depends_on must be a unique list of at most 20 ids")
            deps = []
        if isinstance(service_id, str):
            dependencies[service_id] = list(deps)
    for service_id, deps in dependencies.items():
        for dependency in deps:
            if dependency not in service_ids:
                errors.append(
                    f"service {service_id!r} references unknown dependency {dependency!r}"
                )
            if dependency == service_id:
                errors.append(f"service {service_id!r} cannot depend on itself")
    if _has_dependency_cycle(dependencies):
        errors.append("service dependency graph must be acyclic")

    actions = normalized.get("actions")
    action_ids: set[str] = set()
    if not isinstance(actions, list) or not 1 <= len(actions) <= MAX_ACTIONS:
        errors.append(f"campaign actions must contain 1..{MAX_ACTIONS} entries")
        actions = []
    for index, action in enumerate(actions):
        label = f"action[{index}]"
        if not isinstance(action, dict) or set(action) != _ACTION_FIELDS:
            errors.append(f"{label} fields are incomplete or unsupported")
            continue
        action_id = action.get("action_id")
        _check_id(action_id, f"{label} action_id", errors)
        if action_id in action_ids:
            errors.append(f"duplicate action_id {action_id!r}")
        if isinstance(action_id, str):
            action_ids.add(action_id)
        _check_text(action.get("name"), f"{label} name", errors)
        _check_id(action.get("supplier_id"), f"{label} supplier_id", errors)
        for field, maximum in (
            ("planning_service_ids", 20),
            ("beneficiary_groups", 20),
            ("prerequisite_action_ids", MAX_ACTIONS),
            ("exclusive_with_action_ids", MAX_ACTIONS),
        ):
            values = action.get(field)
            if not _id_list(
                values,
                maximum=maximum,
                nonempty=field in {"planning_service_ids", "beneficiary_groups"},
            ):
                errors.append(f"{label} {field} must be a unique bounded list of ids")
        for service_id in action.get("planning_service_ids", []):
            if service_id not in service_ids:
                errors.append(f"{label} references unknown service {service_id!r}")
        demand = action.get("resource_demand")
        if not isinstance(demand, dict) or set(demand) != _RESOURCE_FIELDS:
            errors.append(f"{label} resource_demand fields are incomplete or unsupported")
        else:
            for field in sorted(_RESOURCE_FIELDS):
                value = demand.get(field)
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 0 <= value <= 1_000_000
                ):
                    errors.append(f"{label} {field} must be an integer from 0 to 1000000")
        report = action.get("defender_report")
        if not isinstance(report, Mapping):
            errors.append(f"{label} defender_report must be an object")
        else:
            report_errors = verify_defender_report(report)
            if report_errors:
                errors.append(f"{label} invalid DefenderTwin report: {'; '.join(report_errors)}")
    action_map = {item.get("action_id"): item for item in actions if isinstance(item, dict)}
    for action_id, action in action_map.items():
        for field in ("prerequisite_action_ids", "exclusive_with_action_ids"):
            for reference in action.get(field, []):
                if reference not in action_ids:
                    errors.append(
                        f"action {action_id!r} {field} references unknown action {reference!r}"
                    )
                if reference == action_id:
                    errors.append(f"action {action_id!r} cannot reference itself in {field}")
        for reference in action.get("exclusive_with_action_ids", []):
            peer = action_map.get(reference, {})
            if action_id not in peer.get("exclusive_with_action_ids", []):
                errors.append(f"action exclusion {action_id!r}/{reference!r} must be symmetric")
    if _has_action_prerequisite_cycle(action_map):
        errors.append("action prerequisite graph must be acyclic")

    scenarios = normalized.get("scenarios")
    scenario_ids: set[str] = set()
    if not isinstance(scenarios, list) or not 1 <= len(scenarios) <= 20:
        errors.append("campaign scenarios must contain 1..20 entries")
        scenarios = []
    for index, scenario in enumerate(scenarios):
        label = f"scenario[{index}]"
        if not isinstance(scenario, dict) or set(scenario) != _SCENARIO_FIELDS:
            errors.append(f"{label} fields are incomplete or unsupported")
            continue
        scenario_id = scenario.get("scenario_id")
        _check_id(scenario_id, f"{label} scenario_id", errors)
        if scenario_id in scenario_ids:
            errors.append(f"duplicate scenario_id {scenario_id!r}")
        if isinstance(scenario_id, str):
            scenario_ids.add(scenario_id)
        _check_text(scenario.get("name"), f"{label} name", errors)
        unavailable = scenario.get("unavailable_action_ids")
        if not _id_list(unavailable, maximum=MAX_ACTIONS):
            errors.append(f"{label} unavailable_action_ids must be a unique bounded list of ids")
        for action_id in unavailable if isinstance(unavailable, list) else []:
            if action_id not in action_ids:
                errors.append(f"{label} references unknown action {action_id!r}")

    constraints = normalized.get("constraints")
    if not isinstance(constraints, dict) or set(constraints) != _CONSTRAINT_FIELDS:
        errors.append("campaign constraints fields are incomplete or unsupported")
    else:
        for field in (
            "max_budget_units",
            "max_workforce_units",
            "max_disruption_units",
        ):
            value = constraints.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000:
                errors.append(f"constraint {field} must be an integer from 0 to 1000000")
        for field, high in (
            ("max_actions", MAX_ACTIONS),
            ("max_actions_per_supplier", MAX_ACTIONS),
        ):
            value = constraints.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= high:
                errors.append(f"constraint {field} must be an integer from 1 to {high}")
        for field, known in (
            ("required_service_ids", service_ids),
            (
                "required_beneficiary_groups",
                {
                    group
                    for action in actions
                    if isinstance(action, dict)
                    for group in action.get("beneficiary_groups", [])
                },
            ),
        ):
            values = constraints.get(field)
            if not _id_list(values, maximum=50):
                errors.append(f"constraint {field} must be a unique bounded list of ids")
            for value in values if isinstance(values, list) else []:
                if value not in known:
                    errors.append(f"constraint {field} references unknown id {value!r}")
    return tuple(dict.fromkeys(errors))


def analyze_campaign(campaign: Mapping[str, Any]) -> dict[str, Any]:
    """Enumerate all eligible action subsets and return the exact Pareto frontier."""

    errors = validate_campaign(campaign)
    if errors:
        raise ValueError("invalid ResilienceGraph campaign: " + "; ".join(errors))
    normalized = _json_clone(campaign)
    services = {item["service_id"]: item for item in normalized["services"]}
    actions = {item["action_id"]: item for item in normalized["actions"]}
    eligibility = [_candidate_eligibility(item) for item in normalized["actions"]]
    eligible_ids = sorted(item["action_id"] for item in eligibility if item["eligible"])
    excluded = [item for item in eligibility if not item["eligible"]]

    feasible_count = 0
    fully_robust = False
    frontier: list[dict[str, Any]] = []
    for mask in range(1 << len(eligible_ids)):
        selected = tuple(
            action_id for index, action_id in enumerate(eligible_ids) if mask & (1 << index)
        )
        if _constraint_failures(selected, actions, normalized["constraints"]):
            continue
        feasible_count += 1
        candidate = _score_portfolio(selected, actions, services, normalized)
        fully_robust = fully_robust or candidate["robust_scenario_count"] == len(
            normalized["scenarios"]
        )
        if any(_dominates(existing, candidate) for existing in frontier):
            continue
        frontier = [existing for existing in frontier if not _dominates(candidate, existing)]
        frontier.append(candidate)

    frontier.sort(key=lambda item: item["portfolio_id"])
    reference = min(frontier, key=_reference_key) if frontier else None
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": protocol_sha256(),
        "analyzer": ANALYZER,
        "campaign_sha256": normalized["campaign_sha256"],
        "campaign": normalized,
        "candidate_eligibility": eligibility,
        "enumeration": {
            "eligible_action_count": len(eligible_ids),
            "total_subsets": 1 << len(eligible_ids),
            "feasible_portfolio_count": feasible_count,
            "frontier_portfolio_count": len(frontier),
            "complete": True,
            "action_limit": MAX_ACTIONS,
        },
        "summary": {
            "outcome": "decision_ready" if frontier else "no_feasible_portfolio",
            "candidate_count": len(actions),
            "eligible_candidate_count": len(eligible_ids),
            "excluded_candidate_count": len(excluded),
            "service_count": len(services),
            "scenario_count": len(normalized["scenarios"]),
            "fully_robust_portfolio_exists": fully_robust,
            "reference_portfolio_id": reference["portfolio_id"] if reference else None,
            "reference_is_recommendation": False,
            "content_fields_processed": 0,
            "live_system_actions": 0,
        },
        "frontier": frontier,
        "reference_selection": reference,
        "decision_authority": normalized["decision_owner"],
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_report(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Recompute a ResilienceGraph report from its embedded campaign."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if report.get("report_type") != REPORT_TYPE:
        errors.append("unsupported ResilienceGraph report type")
    if report.get("protocol_version") != PROTOCOL_VERSION:
        errors.append("unsupported ResilienceGraph protocol version")
    if report.get("protocol_sha256") != protocol_sha256():
        errors.append("ResilienceGraph protocol_sha256 does not match this implementation")
    campaign = report.get("campaign")
    if not isinstance(campaign, Mapping):
        errors.append("report campaign must be an object")
        return tuple(errors)
    try:
        expected = analyze_campaign(campaign)
    except (TypeError, ValueError) as exc:
        errors.append(f"invalid embedded campaign: {exc}")
    else:
        if _json_clone(report) != expected:
            errors.append("ResilienceGraph report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def frontier_csv_rows(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return flat, deterministic rows for decision-review tooling."""

    errors = verify_report(report)
    if errors:
        raise ValueError("invalid ResilienceGraph report: " + "; ".join(errors))
    rows = []
    reference_id = report["summary"]["reference_portfolio_id"]
    for item in report["frontier"]:
        resources = item["resources"]
        rows.append(
            {
                "portfolio_id": item["portfolio_id"],
                "reference_selection": item["portfolio_id"] == reference_id,
                "selected_action_ids": ";".join(item["selected_action_ids"]),
                "robust_scenario_count": item["robust_scenario_count"],
                "scenario_count": len(item["scenario_results"]),
                "worst_direct_service_weight": item["worst_direct_service_weight"],
                "worst_dependency_reach_weight": item["worst_dependency_reach_weight"],
                "worst_beneficiary_group_count": item["worst_beneficiary_group_count"],
                "budget_units": resources["budget_units"],
                "workforce_units": resources["workforce_units"],
                "disruption_units": resources["disruption_units"],
            }
        )
    return rows


def _candidate_eligibility(action: Mapping[str, Any]) -> dict[str, Any]:
    report = action["defender_report"]
    reasons = []
    if report["summary"]["outcome"] != "effective_and_safe":
        reasons.append(f"DefenderTwin outcome is {report['summary']['outcome']}")
    if report["summary"].get("trusted_defender_gate") is not True:
        reasons.append("Trusted Defender Gate did not pass")
    if report["summary"].get("content_fields_processed") != 0:
        reasons.append("DefenderTwin privacy boundary was not preserved")
    return {
        "action_id": action["action_id"],
        "eligible": not reasons,
        "reasons": reasons,
        "defender_report_sha256": report["report_sha256"],
        "defender_outcome": report["summary"]["outcome"],
        "planning_mapping_verified_by_defendertwin": False,
    }


def _constraint_failures(
    selected: Sequence[str],
    actions: Mapping[str, Mapping[str, Any]],
    constraints: Mapping[str, Any],
) -> tuple[str, ...]:
    chosen = set(selected)
    demand = _resource_totals(selected, actions)
    failures = []
    for resource in _RESOURCE_FIELDS:
        if demand[resource] > constraints[f"max_{resource}"]:
            failures.append(f"{resource} ceiling exceeded")
    if len(selected) > constraints["max_actions"]:
        failures.append("action ceiling exceeded")
    suppliers: dict[str, int] = {}
    for action_id in selected:
        action = actions[action_id]
        supplier = action["supplier_id"]
        suppliers[supplier] = suppliers.get(supplier, 0) + 1
        if not set(action["prerequisite_action_ids"]) <= chosen:
            failures.append(f"{action_id} prerequisite missing")
        if set(action["exclusive_with_action_ids"]) & chosen:
            failures.append(f"{action_id} exclusion violated")
    if any(count > constraints["max_actions_per_supplier"] for count in suppliers.values()):
        failures.append("supplier concentration ceiling exceeded")
    services = {
        service_id
        for action_id in selected
        for service_id in actions[action_id]["planning_service_ids"]
    }
    groups = {group for action_id in selected for group in actions[action_id]["beneficiary_groups"]}
    if not set(constraints["required_service_ids"]) <= services:
        failures.append("required direct-service floor not met")
    if not set(constraints["required_beneficiary_groups"]) <= groups:
        failures.append("required beneficiary-group floor not met")
    return tuple(dict.fromkeys(failures))


def _score_portfolio(
    selected: Sequence[str],
    actions: Mapping[str, Mapping[str, Any]],
    services: Mapping[str, Mapping[str, Any]],
    campaign: Mapping[str, Any],
) -> dict[str, Any]:
    scenario_results = []
    for scenario in campaign["scenarios"]:
        active = tuple(sorted(set(selected) - set(scenario["unavailable_action_ids"])))
        direct = {
            service_id
            for action_id in active
            for service_id in actions[action_id]["planning_service_ids"]
        }
        reach = _downstream_reach(direct, services) - direct
        groups = sorted(
            {group for action_id in active for group in actions[action_id]["beneficiary_groups"]}
        )
        missing_services = sorted(set(campaign["constraints"]["required_service_ids"]) - direct)
        missing_groups = sorted(
            set(campaign["constraints"]["required_beneficiary_groups"]) - set(groups)
        )
        scenario_results.append(
            {
                "scenario_id": scenario["scenario_id"],
                "active_action_ids": list(active),
                "unavailable_selected_action_ids": sorted(set(selected) - set(active)),
                "direct_service_ids": sorted(direct),
                "dependency_reach_service_ids": sorted(reach),
                "beneficiary_groups": groups,
                "direct_service_weight": sum(
                    services[item]["criticality_weight"] for item in direct
                ),
                "dependency_reach_weight": sum(
                    services[item]["criticality_weight"] for item in reach
                ),
                "requirements_met": not missing_services and not missing_groups,
                "missing_required_service_ids": missing_services,
                "missing_required_beneficiary_groups": missing_groups,
            }
        )
    digest = canonical_sha256({"selected_action_ids": list(selected)})[:16]
    return {
        "portfolio_id": f"portfolio-{digest}",
        "selected_action_ids": list(selected),
        "resources": _resource_totals(selected, actions),
        "supplier_action_counts": _supplier_counts(selected, actions),
        "robust_scenario_count": sum(item["requirements_met"] for item in scenario_results),
        "worst_direct_service_weight": min(
            item["direct_service_weight"] for item in scenario_results
        ),
        "worst_dependency_reach_weight": min(
            item["dependency_reach_weight"] for item in scenario_results
        ),
        "worst_beneficiary_group_count": min(
            len(item["beneficiary_groups"]) for item in scenario_results
        ),
        "scenario_results": scenario_results,
    }


def _dominates(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    max_fields = (
        "robust_scenario_count",
        "worst_direct_service_weight",
        "worst_dependency_reach_weight",
        "worst_beneficiary_group_count",
    )
    resources = ("budget_units", "workforce_units", "disruption_units")
    no_worse = (
        all(left[field] >= right[field] for field in max_fields)
        and all(left["resources"][field] <= right["resources"][field] for field in resources)
        and len(left["selected_action_ids"]) <= len(right["selected_action_ids"])
    )
    strictly_better = (
        any(left[field] > right[field] for field in max_fields)
        or any(left["resources"][field] < right["resources"][field] for field in resources)
        or len(left["selected_action_ids"]) < len(right["selected_action_ids"])
    )
    return no_worse and strictly_better


def _reference_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    resources = item["resources"]
    return (
        -item["robust_scenario_count"],
        -item["worst_direct_service_weight"],
        -item["worst_dependency_reach_weight"],
        -item["worst_beneficiary_group_count"],
        resources["budget_units"],
        resources["workforce_units"],
        resources["disruption_units"],
        len(item["selected_action_ids"]),
        tuple(item["selected_action_ids"]),
    )


def _resource_totals(
    selected: Sequence[str], actions: Mapping[str, Mapping[str, Any]]
) -> dict[str, int]:
    return {
        field: sum(actions[action_id]["resource_demand"][field] for action_id in selected)
        for field in sorted(_RESOURCE_FIELDS)
    }


def _supplier_counts(
    selected: Sequence[str], actions: Mapping[str, Mapping[str, Any]]
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for action_id in selected:
        supplier = actions[action_id]["supplier_id"]
        counts[supplier] = counts.get(supplier, 0) + 1
    return dict(sorted(counts.items()))


def _downstream_reach(starting: set[str], services: Mapping[str, Mapping[str, Any]]) -> set[str]:
    downstream: dict[str, set[str]] = {service_id: set() for service_id in services}
    for service_id, service in services.items():
        for dependency in service["depends_on"]:
            downstream[dependency].add(service_id)
    reached = set(starting)
    queue = list(starting)
    while queue:
        current = queue.pop()
        for dependent in downstream[current]:
            if dependent not in reached:
                reached.add(dependent)
                queue.append(dependent)
    return reached


def _has_dependency_cycle(dependencies: Mapping[str, Sequence[str]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for dependency in dependencies.get(node, []):
            if dependency in dependencies and visit(dependency):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in dependencies)


def _has_action_prerequisite_cycle(actions: Mapping[str, Mapping[str, Any]]) -> bool:
    graph = {
        action_id: [item for item in action.get("prerequisite_action_ids", []) if item in actions]
        for action_id, action in actions.items()
        if isinstance(action_id, str)
    }
    return _has_dependency_cycle(graph)


def _check_text(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 2_000:
        errors.append(f"{label} must be a non-empty string of at most 2000 characters")


def _check_id(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case id of at most 100 characters")


def _id_list(value: Any, *, maximum: int, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (bool(value) or not nonempty)
        and len(value) <= maximum
        and len(value) == len(set(value))
        and all(
            isinstance(item, str) and len(item) <= 100 and _ID.fullmatch(item) for item in value
        )
    )


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
