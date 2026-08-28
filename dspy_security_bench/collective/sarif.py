"""SARIF 2.1.0 export for CollectiveGuard structural findings."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.collective.proof import RULES, verify_collective_report


def collective_report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    errors = verify_collective_report(report)
    if errors:
        raise ValueError("invalid CollectiveGuard report: " + "; ".join(errors))
    present = sorted({finding["rule_id"] for finding in report["findings"]})
    levels = {"critical": "error", "high": "error", "medium": "warning"}
    scores = {"critical": "9.0", "high": "7.5", "medium": "5.0"}
    rules = [
        {
            "id": rule_id,
            "name": RULES[rule_id]["title"].replace(" ", ""),
            "shortDescription": {"text": RULES[rule_id]["title"]},
            "help": {"text": RULES[rule_id]["repair"]},
            "properties": {
                "security-severity": scores[RULES[rule_id]["severity"]],
                "tags": ["security", "ai-agent", "containment", "collectiveguard"],
                "controlObjective": RULES[rule_id]["objective"],
            },
        }
        for rule_id in present
    ]
    results = [
        {
            "ruleId": finding["rule_id"],
            "level": levels[finding["severity"]],
            "message": {
                "text": (
                    f"{finding['title']} at {finding['event_id']} (+{finding['offset_seconds']}s)."
                )
            },
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": finding["event_id"],
                            "fullyQualifiedName": (
                                f"{report['scenario']['scenario_id']}::{finding['event_id']}"
                            ),
                            "kind": "event",
                        }
                    ]
                }
            ],
            "properties": {
                "scenarioSha256": report["scenario_sha256"],
                "runIds": finding["run_ids"],
                "resourceIds": finding["resource_ids"],
                "evidenceEventIds": finding["evidence_event_ids"],
                "controlObjective": finding["control_objective"],
                "repairHint": finding["repair_hint"],
            },
        }
        for finding in report["findings"]
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench CollectiveGuard",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "reportSha256": report["report_sha256"],
                    "contentFieldsProcessed": report["summary"]["content_fields_processed"],
                    "claimBoundary": report["disclaimer"],
                },
            }
        ],
    }
