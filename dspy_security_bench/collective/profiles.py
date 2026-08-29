"""Owner-selectable CollectiveGuard adoption profiles and informative federal exports."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from dspy_security_bench.collective.proof import CONTROL_OBJECTIVES, RULES
from dspy_security_bench.collective.v2 import verify_report
from dspy_security_bench.mission.loader import canonical_sha256

PROFILE_VERSION = "collectiveguard-adoption-profiles-v1"
ASSESSMENT_TYPE = "dspy-security-bench-collective-profile-assessment"
OSCAL_VERSION = "1.2.2"
DISCLAIMER = (
    "CollectiveGuard adoption profiles are owner-adjustable engineering defaults and informative "
    "crosswalks. They do not establish NIST, federal, sector, regulatory, contractual, or control "
    "conformance; replace them with system-specific requirements and accountable review."
)

_OBJECTIVE_CROSSWALK: dict[str, dict[str, list[str]]] = {
    "workload_isolation": {
        "nist_csf_2_0_functions": ["PROTECT", "RESPOND"],
        "nist_ai_rmf_functions": ["MAP", "MEASURE", "MANAGE"],
        "incident_response_stages": ["Detect", "Respond"],
    },
    "network_egress": {
        "nist_csf_2_0_functions": ["PROTECT", "DETECT"],
        "nist_ai_rmf_functions": ["MAP", "MEASURE", "MANAGE"],
        "incident_response_stages": ["Detect", "Respond"],
    },
    "cross_run_isolation": {
        "nist_csf_2_0_functions": ["PROTECT", "DETECT"],
        "nist_ai_rmf_functions": ["GOVERN", "MAP", "MEASURE"],
        "incident_response_stages": ["Detect", "Respond"],
    },
    "credential_boundary": {
        "nist_csf_2_0_functions": ["PROTECT"],
        "nist_ai_rmf_functions": ["GOVERN", "MAP", "MANAGE"],
        "incident_response_stages": ["Respond"],
    },
    "evaluator_integrity": {
        "nist_csf_2_0_functions": ["PROTECT", "DETECT"],
        "nist_ai_rmf_functions": ["GOVERN", "MEASURE", "MANAGE"],
        "incident_response_stages": ["Detect", "Respond", "Recover"],
    },
    "monitoring": {
        "nist_csf_2_0_functions": ["DETECT"],
        "nist_ai_rmf_functions": ["MEASURE", "MANAGE"],
        "incident_response_stages": ["Detect", "Respond"],
    },
    "incident_response": {
        "nist_csf_2_0_functions": ["RESPOND", "RECOVER"],
        "nist_ai_rmf_functions": ["GOVERN", "MANAGE"],
        "incident_response_stages": ["Respond", "Recover"],
    },
}


def _profile(
    profile_id: str,
    title: str,
    deployment_context: str,
    required_sources: list[str],
    escalation_seconds: int,
    containment_seconds: int,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "profile_version": PROFILE_VERSION,
        "profile_id": profile_id,
        "title": title,
        "deployment_context": deployment_context,
        "required_source_types": sorted(required_sources),
        "response_objectives": {
            "max_escalation_seconds": escalation_seconds,
            "max_containment_seconds": containment_seconds,
            "independent_containment_required": True,
            "evidence_preservation_required": True,
        },
        "control_objectives": [
            {
                "objective_id": objective,
                "minimum_independent_controls": 2,
                "informative_crosswalk": deepcopy(_OBJECTIVE_CROSSWALK[objective]),
            }
            for objective in CONTROL_OBJECTIVES
        ],
        "mapping_status": "informative-not-determinative",
        "claim_boundary": DISCLAIMER,
    }
    payload["profile_sha256"] = canonical_sha256(payload)
    return payload


PROFILES: dict[str, dict[str, Any]] = {
    "enterprise": _profile(
        "enterprise",
        "Enterprise agent collective",
        "Business systems with bounded delegated authority and formal incident ownership.",
        ["control", "identity", "network", "response", "runtime"],
        900,
        1800,
    ),
    "frontier-lab": _profile(
        "frontier-lab",
        "Frontier AI research and evaluation",
        "High-capability model evaluation, red-team, and autonomous research workloads.",
        ["control", "evaluator", "identity", "network", "response", "runtime"],
        300,
        600,
    ),
    "federal-high-impact": _profile(
        "federal-high-impact",
        "Federal high-impact AI system",
        "Owner-reviewed evidence defaults for consequential federal AI deployments.",
        ["control", "evaluator", "identity", "network", "response", "runtime"],
        300,
        600,
    ),
    "critical-infrastructure": _profile(
        "critical-infrastructure",
        "Critical infrastructure agent collective",
        "Safety- and continuity-sensitive environments with independently operated containment.",
        ["control", "evaluator", "identity", "network", "response", "runtime"],
        120,
        300,
    ),
}


def built_in_profile(profile_id: str) -> dict[str, Any]:
    if profile_id not in PROFILES:
        raise ValueError(f"unknown CollectiveGuard adoption profile {profile_id!r}")
    return deepcopy(PROFILES[profile_id])


def verify_profile(profile: Mapping[str, Any]) -> tuple[str, ...]:
    expected = PROFILES.get(str(profile.get("profile_id")))
    if expected is None:
        return ("profile_id is not a frozen built-in profile",)
    if profile != expected:
        return ("profile does not match the frozen built-in content",)
    return ()


def assess_profile(report: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, Any]:
    report_errors = verify_report(report)
    if report_errors:
        raise ValueError("invalid CollectiveGuard v2 report: " + "; ".join(report_errors))
    profile_errors = verify_profile(profile)
    if profile_errors:
        raise ValueError("invalid adoption profile: " + "; ".join(profile_errors))
    source_by_type = {item["source_type"]: item for item in report["source_coverage"]}
    missing_sources = [
        source_type
        for source_type in profile["required_source_types"]
        if source_by_type[source_type]["status"] != "complete"
    ]
    base_policy = report["scenario"]["collective_scenario"]["policy"]
    response_gaps = []
    if (
        base_policy["escalation_sla_seconds"]
        > profile["response_objectives"]["max_escalation_seconds"]
    ):
        response_gaps.append("escalation_sla_exceeds_profile")
    if (
        base_policy["containment_sla_seconds"]
        > profile["response_objectives"]["max_containment_seconds"]
    ):
        response_gaps.append("containment_sla_exceeds_profile")
    coverage_by_objective = {
        item["objective"]: item for item in report["base_report"]["control_coverage"]
    }
    findings_by_objective: dict[str, list[str]] = {item: [] for item in CONTROL_OBJECTIVES}
    for finding in report["findings"]:
        objective = RULES[finding["rule_id"]]["objective"]
        findings_by_objective[objective].append(finding["rule_id"])
    objectives = []
    for configured in profile["control_objectives"]:
        objective = configured["objective_id"]
        coverage = coverage_by_objective[objective]
        finding_ids = sorted(set(findings_by_objective[objective]))
        if finding_ids or coverage["coverage_status"] != "sufficient":
            status = "not_satisfied"
        elif report["summary"]["status"] == "insufficient_evidence" or missing_sources:
            status = "insufficient_evidence"
        else:
            status = "satisfied"
        objectives.append(
            {
                "objective_id": objective,
                "status": status,
                "observed_rule_ids": finding_ids,
                "control_coverage_status": coverage["coverage_status"],
                "independent_failure_domain_count": len(coverage["independent_failure_domains"]),
                "informative_crosswalk": deepcopy(configured["informative_crosswalk"]),
            }
        )
    if (
        missing_sources
        or response_gaps
        or any(item["status"] != "satisfied" for item in objectives)
    ):
        status = "review_required"
    else:
        status = "profile_objectives_observed"
    assessment: dict[str, Any] = {
        "schema_version": 1,
        "assessment_type": ASSESSMENT_TYPE,
        "profile": deepcopy(dict(profile)),
        "collective_report_sha256": report["report_sha256"],
        "summary": {
            "status": status,
            "satisfied_objectives": sum(item["status"] == "satisfied" for item in objectives),
            "not_satisfied_objectives": sum(
                item["status"] == "not_satisfied" for item in objectives
            ),
            "insufficient_evidence_objectives": sum(
                item["status"] == "insufficient_evidence" for item in objectives
            ),
            "missing_source_types": missing_sources,
            "response_gaps": response_gaps,
        },
        "objectives": objectives,
        "mapping_status": "informative-not-determinative",
        "claim_boundary": DISCLAIMER,
    }
    assessment["assessment_sha256"] = canonical_sha256(assessment)
    return assessment


def verify_assessment(payload: Mapping[str, Any], report: Mapping[str, Any]) -> tuple[str, ...]:
    errors = list(verify_report(report))
    profile = payload.get("profile")
    if not isinstance(profile, Mapping):
        errors.append("assessment profile must be an object")
        return tuple(dict.fromkeys(errors))
    errors.extend(verify_profile(profile))
    if errors:
        return tuple(dict.fromkeys(errors))
    expected = assess_profile(report, profile)
    if payload != expected:
        errors.append("assessment does not recompute")
    return tuple(dict.fromkeys(errors))


def export_oscal(assessment: Mapping[str, Any]) -> dict[str, Any]:
    """Export informative OSCAL Assessment Results without claiming control satisfaction."""

    if assessment.get("assessment_type") != ASSESSMENT_TYPE:
        raise ValueError("unsupported CollectiveGuard profile assessment")
    digest = assessment.get("assessment_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("assessment_sha256 is invalid")
    namespace = f"https://github.com/immu4989/dspy-security-bench/collective/{digest}"
    start = "1970-01-01T00:00:00Z"
    observations = []
    findings = []
    for item in assessment["objectives"]:
        objective = item["objective_id"]
        observation_uuid = str(uuid5(NAMESPACE_URL, namespace + "/observation/" + objective))
        observations.append(
            {
                "uuid": observation_uuid,
                "title": f"CollectiveGuard objective: {objective}",
                "description": (
                    "Content-free structural observation with an informative, non-determinative crosswalk."
                ),
                "methods": ["TEST"],
                "collected": start,
                "props": [
                    {"name": "objective-id", "value": objective},
                    {"name": "local-status", "value": item["status"]},
                    {"name": "mapping-status", "value": "informative-not-determinative"},
                ],
                "remarks": DISCLAIMER,
            }
        )
        if item["status"] != "satisfied":
            findings.append(
                {
                    "uuid": str(uuid5(NAMESPACE_URL, namespace + "/finding/" + objective)),
                    "title": f"Owner review required: {objective}",
                    "description": "Local assurance objective was not satisfied or evidence was incomplete.",
                    "target": {
                        "type": "objective-id",
                        "target-id": objective,
                        "status": {"state": "not-satisfied"},
                    },
                    "related-observations": [{"observation-uuid": observation_uuid}],
                    "remarks": DISCLAIMER,
                }
            )
    return {
        "$schema": (
            "https://github.com/usnistgov/OSCAL/releases/download/v1.2.2/"
            "oscal_assessment-results_schema.json"
        ),
        "assessment-results": {
            "uuid": str(uuid5(NAMESPACE_URL, namespace)),
            "metadata": {
                "title": f"CollectiveGuard — {assessment['profile']['title']}",
                "last-modified": start,
                "version": digest[:12],
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "collectiveguard-assessment-sha256", "value": digest},
                    {"name": "mapping-status", "value": "informative-not-determinative"},
                    {"name": "non-certifying", "value": "true"},
                ],
                "remarks": DISCLAIMER,
            },
            "import-ap": {"href": "urn:collectiveguard:owner-supplied-assessment-plan"},
            "results": [
                {
                    "uuid": str(uuid5(NAMESPACE_URL, namespace + "/result")),
                    "title": "CollectiveGuard provenance-aware structural assessment",
                    "description": "Owner-reviewed local assurance observations.",
                    "start": start,
                    "reviewed-controls": {"control-selections": []},
                    "observations": observations,
                    "findings": findings,
                    "remarks": DISCLAIMER,
                }
            ],
        },
    }
