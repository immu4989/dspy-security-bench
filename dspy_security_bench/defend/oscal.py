"""Informative OSCAL 1.2.2 export for DefenderTwin reports."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from dspy_security_bench.defend.protocol import DISCLAIMER, verify_report


def report_to_oscal(report: Mapping[str, Any]) -> dict[str, Any]:
    errors = verify_report(report)
    if errors:
        raise ValueError("invalid DefenderTwin report: " + "; ".join(errors))
    digest = report["report_sha256"]
    namespace = f"https://github.com/immu4989/dspy-security-bench/defend/{digest}"
    start = "1970-01-01T00:00:00Z"
    observations = []
    for weakness in report["mission"]["weaknesses"]:
        weakness_id = weakness["weakness_id"]
        resolved = any(
            item["weakness_id"] == weakness_id and item["restored_required_state"]
            for item in report["remediations"]
        )
        observations.append(
            {
                "uuid": str(uuid5(NAMESPACE_URL, namespace + "/observation/" + weakness_id)),
                "title": f"DefenderTwin weakness: {weakness_id}",
                "description": "Synthetic before/after remediation observation.",
                "methods": ["TEST"],
                "collected": start,
                "props": [
                    {"name": "weakness-id", "value": weakness_id},
                    {"name": "local-status", "value": "restored" if resolved else "not-restored"},
                    {"name": "mapping-status", "value": "informative-not-determinative"},
                ],
                "remarks": DISCLAIMER,
            }
        )
    findings = []
    for index, item in enumerate(report["findings"]):
        findings.append(
            {
                "uuid": str(
                    uuid5(NAMESPACE_URL, namespace + f"/finding/{index}/{item['rule_id']}")
                ),
                "title": item["title"],
                "description": item["detail"],
                "target": {
                    "type": "objective-id",
                    "target-id": item["subject_id"],
                    "status": {"state": "not-satisfied"},
                },
                "remarks": DISCLAIMER,
            }
        )
    result: dict[str, Any] = {
        "uuid": str(uuid5(NAMESPACE_URL, namespace + "/result")),
        "title": "Verified cyber-defense remediation assessment",
        "description": "Synthetic, owner-reviewed remediation observations.",
        "start": start,
        "reviewed-controls": {
            "control-selections": [
                {
                    "description": (
                        "All controls in the owner-supplied assessment plan remain in scope; "
                        "DefenderTwin does not determine control satisfaction."
                    ),
                    "include-all": {},
                    "remarks": DISCLAIMER,
                }
            ]
        },
        "observations": observations,
        "remarks": DISCLAIMER,
    }
    if findings:
        result["findings"] = findings
    return {
        "$schema": "https://github.com/usnistgov/OSCAL/releases/download/v1.2.2/oscal_assessment-results_schema.json",
        "assessment-results": {
            "uuid": str(uuid5(NAMESPACE_URL, namespace)),
            "metadata": {
                "title": f"DefenderTwin — {report['mission']['title']}",
                "last-modified": start,
                "version": digest[:12],
                "oscal-version": "1.2.2",
                "props": [
                    {"name": "defendertwin-report-sha256", "value": digest},
                    {"name": "mapping-status", "value": "informative-not-determinative"},
                    {"name": "non-certifying", "value": "true"},
                ],
                "remarks": DISCLAIMER,
            },
            "import-ap": {"href": "urn:defendertwin:owner-supplied-assessment-plan"},
            "results": [result],
        },
    }
