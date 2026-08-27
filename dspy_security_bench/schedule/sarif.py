"""SARIF 2.1.0 export for ScheduleProof counterexamples."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.schedule.proof import verify_schedule_report


def schedule_report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    errors = verify_schedule_report(report)
    if errors:
        raise ValueError("invalid ScheduleProof report: " + "; ".join(errors))
    counterexamples = report["counterexamples"]
    rules = [
        {
            "id": item["violation_id"],
            "name": item["title"].replace(" ", ""),
            "shortDescription": {"text": item["title"]},
            "help": {"text": item["repair_hint"]},
            "properties": {"security-severity": "8.0", "tags": ["security", "ai-agent"]},
        }
        for item in counterexamples
    ]
    results = [
        {
            "ruleId": item["violation_id"],
            "level": "error",
            "message": {
                "text": (
                    f"{item['title']} at {item['event_id']}. Minimal schedule prefix: "
                    + " -> ".join(item["schedule_prefix"])
                )
            },
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": item["event_id"],
                            "fullyQualifiedName": (
                                f"{report['scenario']['scenario_id']}::{item['event_id']}"
                            ),
                            "kind": "event",
                        }
                    ]
                }
            ],
            "properties": {
                "scenarioSha256": report["scenario_sha256"],
                "causalEventIds": item["causal_event_ids"],
                "missingHappensBefore": item["missing_happens_before"],
                "repairHint": item["repair_hint"],
            },
        }
        for item in counterexamples
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench ScheduleProof",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "reportSha256": report["report_sha256"],
                    "completeExploration": report["summary"]["complete_exploration"],
                    "unsafeScheduleFractionIsProbability": False,
                },
            }
        ],
    }
