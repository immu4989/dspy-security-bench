"""SARIF export for DefenderTwin remediation findings."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.defend.protocol import RULES, verify_report


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    errors = verify_report(report)
    if errors:
        raise ValueError("invalid DefenderTwin report: " + "; ".join(errors))
    present = sorted({item["rule_id"] for item in report["findings"]})
    levels = {"critical": "error", "high": "error", "medium": "warning"}
    scores = {"critical": "9.0", "high": "7.5", "medium": "5.0"}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench DefenderTwin",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": RULES[rule_id]["title"].replace(" ", ""),
                                "shortDescription": {"text": RULES[rule_id]["title"]},
                                "help": {"text": RULES[rule_id]["repair"]},
                                "properties": {
                                    "security-severity": scores[RULES[rule_id]["severity"]],
                                    "tags": ["security", "ai-agent", "remediation", "defendertwin"],
                                },
                            }
                            for rule_id in present
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": item["rule_id"],
                        "level": levels[item["severity"]],
                        "message": {"text": f"{item['title']}: {item['detail']}"},
                        "locations": [
                            {
                                "logicalLocations": [
                                    {
                                        "name": item["subject_id"],
                                        "fullyQualifiedName": f"{report['mission']['mission_id']}::{item['subject_id']}",
                                        "kind": "resource",
                                    }
                                ]
                            }
                        ],
                        "properties": {
                            "reportSha256": report["report_sha256"],
                            "evidenceIds": item["evidence_ids"],
                            "repairHint": item["repair_hint"],
                        },
                    }
                    for item in report["findings"]
                ],
                "properties": {
                    "outcome": report["summary"]["outcome"],
                    "missionSha256": report["mission_sha256"],
                    "contentFieldsProcessed": 0,
                    "claimBoundary": report["claim_boundary"],
                },
            }
        ],
    }
