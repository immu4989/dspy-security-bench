"""Owner-authored AI BOM disclosure requirements and deterministic findings."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.mlbom import (
    DATA_DISCLOSURE_FIELDS,
    MODEL_DISCLOSURE_FIELDS,
    verify_mlbom_import_report,
)
from dspy_security_bench.supplychain.mlbom import (
    PROTOCOL_VERSION as MLBOM_PROTOCOL_VERSION,
)
from dspy_security_bench.supplychain.spdxai import (
    AI_DISCLOSURE_FIELDS,
    DATASET_DISCLOSURE_FIELDS,
    verify_spdx_ai_import_report,
)
from dspy_security_bench.supplychain.spdxai import (
    PROTOCOL_VERSION as SPDX_AI_PROTOCOL_VERSION,
)

POLICY_TYPE = "dspy-security-bench-ai-disclosure-policy"
POLICY_VERSION = "agentbom-ai-disclosure-policy-v1"
REPORT_TYPE = "AgentBOM AIDisclosurePolicy / Owner-required disclosure findings"
PROTOCOL_VERSION = "agentbom-ai-disclosure-policy-evaluation-v1"
ANALYZER = "deterministic-owner-required-ai-disclosure-evaluator-v1"
MAX_TEXT = 500
MAX_FINDINGS = 20_000
_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CLAIM_BOUNDARY = (
    "AIDisclosurePolicy checks owner-selected disclosure-field presence and bounded relationship "
    "requirements against exactly recomputed CycloneDX 1.7 ML-BOM and SPDX 3.0.1 AI/Dataset "
    "import reports. A requirements_met result means only that the supplied reports contain the "
    "configured fields and relationship evidence. It does not validate field truth or adequacy, "
    "authenticate a supplier, compare hidden values, score a model, determine legal or regulatory "
    "compliance, approve procurement or deployment, certify a system, or authorize operation."
)
LIMITATIONS = (
    "The policy is caller-authored; this project does not prescribe universal required fields or accept risk for the owner.",
    "Field presence is structural evidence only and does not establish accuracy, completeness, freshness, safety, fairness, privacy, or fitness for use.",
    "Both source import reports are exactly recomputed, but the underlying BOM documents and supplier assertions remain unauthenticated.",
    "License relationship findings are structural SPDX profile checks, not legal advice or license compatibility analysis.",
    "SARIF is a review-routing surface; findings are not vulnerabilities and a zero-finding report is not certification or approval.",
    "No network access, raw disclosure processing, ranking, automatic waiver, procurement action, deployment action, or risk acceptance occurs.",
)


def build_ai_disclosure_policy_report(
    policy: Mapping[str, Any],
    cyclonedx_report: Mapping[str, Any],
    cyclonedx_source: Mapping[str, Any],
    spdx_report: Mapping[str, Any],
    spdx_source: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate exact source-bound disclosure reports against owner requirements."""

    parsed_policy = _parse_policy(policy)
    if errors := verify_mlbom_import_report(cyclonedx_report, cyclonedx_source):
        raise ValueError("invalid CycloneDX ML-BOM import report: " + "; ".join(errors))
    if errors := verify_spdx_ai_import_report(spdx_report, spdx_source):
        raise ValueError("invalid SPDX AI import report: " + "; ".join(errors))
    checks: list[dict[str, Any]] = []
    finding_inputs: list[dict[str, Any]] = []
    _evaluate_coverage(
        "cyclonedx",
        cyclonedx_report["model_disclosure_coverage"],
        parsed_policy["cyclonedx"]["required_model_fields"],
        checks,
        finding_inputs,
    )
    _evaluate_coverage(
        "cyclonedx",
        cyclonedx_report["data_disclosure_coverage"],
        parsed_policy["cyclonedx"]["required_dataset_fields"],
        checks,
        finding_inputs,
    )
    _evaluate_coverage(
        "spdx",
        spdx_report["ai_disclosure_coverage"],
        parsed_policy["spdx"]["required_ai_fields"],
        checks,
        finding_inputs,
    )
    _evaluate_coverage(
        "spdx",
        spdx_report["dataset_disclosure_coverage"],
        parsed_policy["spdx"]["required_dataset_fields"],
        checks,
        finding_inputs,
    )
    cdx_unresolved = cyclonedx_report["summary"]["unresolved_dataset_references"]
    if parsed_policy["cyclonedx"]["require_resolved_dataset_references"] and cdx_unresolved:
        finding_inputs.append(
            _finding_input(
                "cyclonedx", "document", "unresolved_dataset_reference", None, cdx_unresolved
            )
        )
    spdx_unresolved = spdx_report["summary"]["unresolved_ai_relationship_references"]
    if parsed_policy["spdx"]["require_resolved_ai_relationships"] and spdx_unresolved:
        finding_inputs.append(
            _finding_input(
                "spdx", "document", "unresolved_relationship_reference", None, spdx_unresolved
            )
        )
    if parsed_policy["spdx"]["require_exactly_one_license_relationship_each"]:
        for item in spdx_report["license_relationship_checks"]:
            if item["status"] != "exactly_one_each":
                finding_inputs.append(
                    _finding_input(
                        "spdx",
                        item["component_id"],
                        "license_relationship_rule",
                        None,
                        abs(1 - item["declared_license_relationships"])
                        + abs(1 - item["concluded_license_relationships"]),
                    )
                )
    if len(finding_inputs) > MAX_FINDINGS:
        raise ValueError(f"AI disclosure policy evaluation exceeds {MAX_FINDINGS} findings")
    findings = [
        {"finding_id": f"finding-{index:05d}", **item}
        for index, item in enumerate(
            sorted(
                finding_inputs,
                key=lambda item: (
                    item["standard"],
                    item["component_id"],
                    item["finding_type"],
                    item["field"] or "",
                ),
            ),
            start=1,
        )
    ]
    status = "requirements_met" if not findings else "owner_review_required"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "policy": {
            "policy_type": POLICY_TYPE,
            "policy_version": POLICY_VERSION,
            "policy_id": parsed_policy["policy_id"],
            "owner": parsed_policy["owner"],
            "canonical_policy_sha256": canonical_sha256(policy),
        },
        "source_reports": {
            "cyclonedx_protocol_version": MLBOM_PROTOCOL_VERSION,
            "cyclonedx_report_sha256": cyclonedx_report["report_sha256"],
            "cyclonedx_source_sha256": canonical_sha256(cyclonedx_source),
            "spdx_protocol_version": SPDX_AI_PROTOCOL_VERSION,
            "spdx_report_sha256": spdx_report["report_sha256"],
            "spdx_source_sha256": canonical_sha256(spdx_source),
        },
        "component_checks": sorted(
            checks, key=lambda item: (item["standard"], item["component_id"])
        ),
        "findings": findings,
        "summary": {
            "status": status,
            "component_checks": len(checks),
            "requirements_met_components": sum(
                item["status"] == "requirements_met" for item in checks
            ),
            "components_requiring_review": sum(
                item["status"] != "requirements_met" for item in checks
            ),
            "finding_count": len(findings),
            "missing_required_fields": sum(
                item["finding_type"] == "missing_required_field" for item in findings
            ),
            "unresolved_reference_findings": sum(
                item["finding_type"]
                in {"unresolved_dataset_reference", "unresolved_relationship_reference"}
                for item in findings
            ),
            "license_relationship_findings": sum(
                item["finding_type"] == "license_relationship_rule" for item in findings
            ),
            "raw_disclosure_values_processed": False,
            "automatic_waivers": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_ai_disclosure_policy_report(
    report: Mapping[str, Any],
    policy: Mapping[str, Any],
    cyclonedx_report: Mapping[str, Any],
    cyclonedx_source: Mapping[str, Any],
    spdx_report: Mapping[str, Any],
    spdx_source: Mapping[str, Any],
) -> tuple[str, ...]:
    """Exactly recompute a policy evaluation and its source import reports."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AgentBOM AIDisclosurePolicy report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
        expected = build_ai_disclosure_policy_report(
            policy, cyclonedx_report, cyclonedx_source, spdx_report, spdx_source
        )
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"AIDisclosurePolicy report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("AIDisclosurePolicy report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def ai_disclosure_policy_report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    """Export deterministic review findings to SARIF without calling them vulnerabilities."""

    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AgentBOM AIDisclosurePolicy report")
    results = []
    for finding in report["findings"]:
        field = f" field {finding['field']}" if finding["field"] else ""
        results.append(
            {
                "ruleId": f"ai-disclosure-{finding['finding_type'].replace('_', '-')}",
                "level": "warning",
                "message": {
                    "text": (
                        f"Owner review required for {finding['standard']} component "
                        f"{finding['component_id']}:{field or ' relationship evidence'}."
                    )
                },
                "properties": deepcopy(finding),
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench AI Disclosure Policy",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": [
                            {
                                "id": f"ai-disclosure-{kind.replace('_', '-')}",
                                "shortDescription": {"text": "AI BOM owner-review requirement"},
                            }
                            for kind in (
                                "missing_required_field",
                                "unresolved_dataset_reference",
                                "unresolved_relationship_reference",
                                "license_relationship_rule",
                            )
                        ],
                    }
                },
                "results": results,
                "properties": {
                    "reportSha256": report["report_sha256"],
                    "automaticActions": 0,
                    "findingsAreVulnerabilities": False,
                },
            }
        ],
    }


def _parse_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, Mapping) or set(policy) != {
        "schema_version",
        "policy_type",
        "policy_version",
        "policy_id",
        "owner",
        "cyclonedx",
        "spdx",
    }:
        raise ValueError("AI disclosure policy has unsupported or missing fields")
    if policy.get("schema_version") != 1 or policy.get("policy_type") != POLICY_TYPE:
        raise ValueError("unsupported AI disclosure policy type")
    if policy.get("policy_version") != POLICY_VERSION:
        raise ValueError(f"AI disclosure policy must use {POLICY_VERSION}")
    policy_id = _required_text(policy.get("policy_id"), "policy_id", identifier=True)
    owner = _required_text(policy.get("owner"), "owner")
    cdx = _profile(
        policy.get("cyclonedx"),
        {
            "required_model_fields": MODEL_DISCLOSURE_FIELDS,
            "required_dataset_fields": DATA_DISCLOSURE_FIELDS,
        },
        "require_resolved_dataset_references",
        "cyclonedx",
    )
    spdx = _profile(
        policy.get("spdx"),
        {
            "required_ai_fields": AI_DISCLOSURE_FIELDS,
            "required_dataset_fields": DATASET_DISCLOSURE_FIELDS,
        },
        "require_resolved_ai_relationships",
        "spdx",
        extra_boolean="require_exactly_one_license_relationship_each",
    )
    if not any(
        value
        for profile in (cdx, spdx)
        for key, value in profile.items()
        if key.startswith("required_")
    ):
        raise ValueError("AI disclosure policy must require at least one disclosure field")
    return {
        "schema_version": 1,
        "policy_type": POLICY_TYPE,
        "policy_version": POLICY_VERSION,
        "policy_id": policy_id,
        "owner": owner,
        "cyclonedx": cdx,
        "spdx": spdx,
    }


def _profile(
    value: object,
    field_sets: Mapping[str, Sequence[str]],
    required_boolean: str,
    label: str,
    *,
    extra_boolean: str | None = None,
) -> dict[str, Any]:
    expected = {*field_sets, required_boolean}
    if extra_boolean:
        expected.add(extra_boolean)
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{label} policy profile has unsupported or missing fields")
    result: dict[str, Any] = {}
    for key, allowed in field_sets.items():
        fields = value[key]
        if not isinstance(fields, list) or not all(isinstance(item, str) for item in fields):
            raise ValueError(f"{label}.{key} must be an array of field names")
        if len(fields) != len(set(fields)) or not set(fields).issubset(allowed):
            raise ValueError(f"{label}.{key} contains duplicate or unsupported fields")
        result[key] = sorted(fields, key=allowed.index)
    for key in (required_boolean, extra_boolean):
        if key is None:
            continue
        if not isinstance(value[key], bool):
            raise ValueError(f"{label}.{key} must be boolean")
        result[key] = value[key]
    return result


def _evaluate_coverage(
    standard: str,
    records: Sequence[Mapping[str, Any]],
    required_fields: Sequence[str],
    checks: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    for record in records:
        present = set(record["present_fields"])
        present_required = [field for field in required_fields if field in present]
        missing = [field for field in required_fields if field not in present]
        checks.append(
            {
                "standard": standard,
                "component_id": record["component_id"],
                "required_fields": list(required_fields),
                "present_required_fields": present_required,
                "missing_required_fields": missing,
                "status": "requirements_met" if not missing else "owner_review_required",
            }
        )
        findings.extend(
            _finding_input(standard, record["component_id"], "missing_required_field", field, 1)
            for field in missing
        )


def _finding_input(
    standard: str,
    component_id: str,
    finding_type: str,
    field: str | None,
    count: int,
) -> dict[str, Any]:
    return {
        "standard": standard,
        "component_id": component_id,
        "finding_type": finding_type,
        "field": field,
        "count": count,
        "automatic_action": False,
    }


def _required_text(value: object, label: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be a non-empty string of at most {MAX_TEXT} characters")
    result = value.strip()
    if identifier and not _ID.fullmatch(result):
        raise ValueError(f"{label} must be a lowercase hyphenated identifier")
    return result
