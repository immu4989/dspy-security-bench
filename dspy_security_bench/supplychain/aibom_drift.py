"""Source-verified, privacy-minimized AI BOM disclosure lifecycle drift."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.aibom_policy import (
    POLICY_TYPE,
    POLICY_VERSION,
    verify_ai_disclosure_policy_report,
)
from dspy_security_bench.supplychain.aibom_policy import (
    PROTOCOL_VERSION as POLICY_EVALUATION_VERSION,
)

REPORT_TYPE = "AgentBOM AIDisclosureDrift / Owner-required disclosure lifecycle change"
PROTOCOL_VERSION = "agentbom-ai-disclosure-drift-v1"
ANALYZER = "deterministic-source-verified-ai-disclosure-drift-v1"
MAX_COMPONENTS = 4_000
MAX_DELTAS = 40_000
CLAIM_BOUNDARY = (
    "AIDisclosureDrift exactly reverifies baseline and candidate AIDisclosurePolicy reports "
    "against the same owner policy and their separately retained CycloneDX 1.7 and SPDX 3.0.1 "
    "sources. It compares only privacy-hashed component identities, configured field names, "
    "structural finding types, and counts. A no_new_disclosure_regression result means only that "
    "the candidate introduced no configured finding and changed no component membership relative "
    "to the supplied baseline. It does not compare raw values, prove truth or adequacy, establish "
    "version lineage, authenticate a supplier, approve a change, certify a system, or authorize operation."
)
LIMITATIONS = (
    "Baseline status is context, not a waiver: persistent gaps remain visible and require the owner's existing disposition process.",
    "Stable privacy-hashed component identity supports comparison but does not prove artifact lineage, supplier continuity, or authorized succession.",
    "Added and removed components require review even when every configured disclosure field is present or a prior gap disappears with removal.",
    "Resolved and improved findings describe structural evidence only rather than truth, adequacy, safety, fairness, privacy, or fitness-for-use improvements.",
    "SARIF routes lifecycle review; results are not vulnerabilities and a clean result is not compliance, certification, approval, or an ATO.",
    "No network access, raw disclosure comparison, ranking, waiver, procurement action, deployment action, risk acceptance, or notification occurs.",
)
_REVIEW_FINDING_STATES = {
    "introduced",
    "worsened",
    "added_component_gap",
    "removed_component_prior_gap",
}


def build_ai_disclosure_drift_report(
    policy: Mapping[str, Any],
    *,
    baseline_evaluation: Mapping[str, Any],
    baseline_cyclonedx_report: Mapping[str, Any],
    baseline_cyclonedx_source: Mapping[str, Any],
    baseline_spdx_report: Mapping[str, Any],
    baseline_spdx_source: Mapping[str, Any],
    candidate_evaluation: Mapping[str, Any],
    candidate_cyclonedx_report: Mapping[str, Any],
    candidate_cyclonedx_source: Mapping[str, Any],
    candidate_spdx_report: Mapping[str, Any],
    candidate_spdx_source: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare two exactly reverified disclosure evaluations without raw values."""

    _verify_snapshot(
        "baseline",
        baseline_evaluation,
        policy,
        baseline_cyclonedx_report,
        baseline_cyclonedx_source,
        baseline_spdx_report,
        baseline_spdx_source,
    )
    _verify_snapshot(
        "candidate",
        candidate_evaluation,
        policy,
        candidate_cyclonedx_report,
        candidate_cyclonedx_source,
        candidate_spdx_report,
        candidate_spdx_source,
    )
    baseline_checks = _component_map(baseline_evaluation)
    candidate_checks = _component_map(candidate_evaluation)
    if len(baseline_checks) > MAX_COMPONENTS or len(candidate_checks) > MAX_COMPONENTS:
        raise ValueError(f"AI disclosure drift exceeds {MAX_COMPONENTS} components per snapshot")
    component_deltas = []
    added: set[tuple[str, str]] = set()
    removed: set[tuple[str, str]] = set()
    for key in sorted(set(baseline_checks) | set(candidate_checks)):
        baseline = baseline_checks.get(key)
        candidate = candidate_checks.get(key)
        if baseline is None:
            state = "added"
            added.add(key)
        elif candidate is None:
            state = "removed"
            removed.add(key)
        else:
            state = "retained"
        component_deltas.append(
            {
                "standard": key[0],
                "component_id": key[1],
                "state": state,
                "baseline_status": baseline["status"] if baseline else None,
                "candidate_status": candidate["status"] if candidate else None,
            }
        )
    baseline_findings = _finding_map(baseline_evaluation)
    candidate_findings = _finding_map(candidate_evaluation)
    if len(baseline_findings) + len(candidate_findings) > MAX_DELTAS:
        raise ValueError(f"AI disclosure drift exceeds {MAX_DELTAS} source findings")
    finding_deltas = []
    for index, key in enumerate(
        sorted(
            set(baseline_findings) | set(candidate_findings),
            key=lambda item: (item[0], item[1], item[2], item[3] or ""),
        ),
        start=1,
    ):
        baseline = baseline_findings.get(key)
        candidate = candidate_findings.get(key)
        baseline_count = baseline["count"] if baseline else None
        candidate_count = candidate["count"] if candidate else None
        component_key = (key[0], key[1])
        if baseline is None:
            state = "added_component_gap" if component_key in added else "introduced"
        elif candidate is None:
            state = "removed_component_prior_gap" if component_key in removed else "resolved"
        elif candidate_count > baseline_count:
            state = "worsened"
        elif candidate_count < baseline_count:
            state = "improved"
        else:
            state = "persistent"
        finding_deltas.append(
            {
                "delta_id": f"delta-{index:05d}",
                "standard": key[0],
                "component_id": key[1],
                "finding_type": key[2],
                "field": key[3],
                "baseline_count": baseline_count,
                "candidate_count": candidate_count,
                "state": state,
                "automatic_action": False,
            }
        )
    states = {
        state: sum(item["state"] == state for item in finding_deltas)
        for state in (
            "introduced",
            "worsened",
            "persistent",
            "improved",
            "resolved",
            "added_component_gap",
            "removed_component_prior_gap",
        )
    }
    regression_count = states["introduced"] + states["worsened"]
    topology_changed = bool(added or removed)
    if regression_count:
        status = "disclosure_regression"
    elif topology_changed:
        status = "component_set_changed"
    else:
        status = "no_new_disclosure_regression"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "policy": {
            "policy_type": POLICY_TYPE,
            "policy_version": POLICY_VERSION,
            "policy_id": baseline_evaluation["policy"]["policy_id"],
            "owner": baseline_evaluation["policy"]["owner"],
            "canonical_policy_sha256": canonical_sha256(policy),
        },
        "baseline": _snapshot_metadata(
            baseline_evaluation,
            baseline_cyclonedx_report,
            baseline_cyclonedx_source,
            baseline_spdx_report,
            baseline_spdx_source,
        ),
        "candidate": _snapshot_metadata(
            candidate_evaluation,
            candidate_cyclonedx_report,
            candidate_cyclonedx_source,
            candidate_spdx_report,
            candidate_spdx_source,
        ),
        "component_deltas": component_deltas,
        "finding_deltas": finding_deltas,
        "summary": {
            "status": status,
            "baseline_finding_count": baseline_evaluation["summary"]["finding_count"],
            "candidate_finding_count": candidate_evaluation["summary"]["finding_count"],
            "candidate_requirements_status": candidate_evaluation["summary"]["status"],
            "retained_components": sum(item["state"] == "retained" for item in component_deltas),
            "added_components": len(added),
            "removed_components": len(removed),
            "component_set_changed": topology_changed,
            "regression_findings": regression_count,
            "introduced_findings": states["introduced"],
            "worsened_findings": states["worsened"],
            "persistent_findings": states["persistent"],
            "improved_findings": states["improved"],
            "resolved_findings": states["resolved"],
            "added_component_gaps": states["added_component_gap"],
            "removed_component_prior_gaps": states["removed_component_prior_gap"],
            "raw_disclosure_values_compared": False,
            "automatic_waivers": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_ai_disclosure_drift_report(
    report: Mapping[str, Any],
    policy: Mapping[str, Any],
    **snapshots: Mapping[str, Any],
) -> tuple[str, ...]:
    """Exactly recompute lifecycle drift from both retained source snapshots."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AgentBOM AIDisclosureDrift report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
        expected = build_ai_disclosure_drift_report(policy, **snapshots)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"AIDisclosureDrift report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("AIDisclosureDrift report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def ai_disclosure_drift_report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    """Route new/worse gaps and component-set changes as review-only SARIF."""

    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AgentBOM AIDisclosureDrift report")
    results = []
    for component in report["component_deltas"]:
        if component["state"] == "retained":
            continue
        results.append(
            {
                "ruleId": f"ai-disclosure-component-{component['state']}",
                "level": "warning",
                "message": {
                    "text": (
                        f"Owner review required: {component['standard']} component "
                        f"{component['component_id']} was {component['state']}."
                    )
                },
                "properties": deepcopy(component),
            }
        )
    for delta in report["finding_deltas"]:
        if delta["state"] not in _REVIEW_FINDING_STATES:
            continue
        results.append(
            {
                "ruleId": f"ai-disclosure-drift-{delta['state'].replace('_', '-')}",
                "level": "warning",
                "message": {
                    "text": (
                        f"Owner review required: {delta['standard']} {delta['component_id']} "
                        f"{delta['finding_type']} is {delta['state'].replace('_', ' ')}."
                    )
                },
                "properties": deepcopy(delta),
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench AI Disclosure Drift",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                    }
                },
                "results": results,
                "properties": {
                    "reportSha256": report["report_sha256"],
                    "resolvedAndImprovedFindings": (
                        report["summary"]["resolved_findings"]
                        + report["summary"]["improved_findings"]
                    ),
                    "automaticActions": 0,
                    "resultsAreVulnerabilities": False,
                },
            }
        ],
    }


def _verify_snapshot(
    label: str,
    evaluation: Mapping[str, Any],
    policy: Mapping[str, Any],
    cyclonedx_report: Mapping[str, Any],
    cyclonedx_source: Mapping[str, Any],
    spdx_report: Mapping[str, Any],
    spdx_source: Mapping[str, Any],
) -> None:
    errors = verify_ai_disclosure_policy_report(
        evaluation, policy, cyclonedx_report, cyclonedx_source, spdx_report, spdx_source
    )
    if errors:
        raise ValueError(f"invalid {label} AI disclosure policy report: {'; '.join(errors)}")


def _component_map(evaluation: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
    result = {}
    for item in evaluation["component_checks"]:
        key = (item["standard"], item["component_id"])
        if key in result:
            raise ValueError(f"duplicate component check: {key[0]} {key[1]}")
        result[key] = item
    return result


def _finding_map(
    evaluation: Mapping[str, Any],
) -> dict[tuple[str, str, str, str | None], Mapping[str, Any]]:
    result = {}
    for item in evaluation["findings"]:
        key = (item["standard"], item["component_id"], item["finding_type"], item["field"])
        if key in result:
            raise ValueError(f"duplicate disclosure finding: {key}")
        result[key] = item
    return result


def _snapshot_metadata(
    evaluation: Mapping[str, Any],
    cyclonedx_report: Mapping[str, Any],
    cyclonedx_source: Mapping[str, Any],
    spdx_report: Mapping[str, Any],
    spdx_source: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "evaluation_protocol_version": POLICY_EVALUATION_VERSION,
        "evaluation_report_sha256": evaluation["report_sha256"],
        "evaluation_status": evaluation["summary"]["status"],
        "cyclonedx_report_sha256": cyclonedx_report["report_sha256"],
        "cyclonedx_source_sha256": canonical_sha256(cyclonedx_source),
        "spdx_report_sha256": spdx_report["report_sha256"],
        "spdx_source_sha256": canonical_sha256(spdx_source),
    }
