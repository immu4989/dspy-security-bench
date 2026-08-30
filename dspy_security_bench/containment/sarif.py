"""SARIF export for ContainmentProof."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.containment.proof import CLAIM_BOUNDARY, PROBES, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported ContainmentProof report")
    rules = [
        {
            "id": probe_id,
            "name": probe_id.replace("-", "_"),
            "shortDescription": {"text": definition["title"]},
            "help": {"text": CLAIM_BOUNDARY},
        }
        for probe_id, definition in PROBES.items()
    ]
    results = []
    for item in report["probe_results"]:
        if item["status"] == "contained":
            continue
        results.append(
            {
                "ruleId": item["probe_id"],
                "level": "error" if item["status"] == "violation_observed" else "warning",
                "message": {"text": f"{item['title']}: {item['status'].replace('_', ' ')}."},
                "properties": {
                    "containmentStatus": item["status"],
                    "sourceIds": item["source_ids"],
                    "automaticActions": 0,
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench ContainmentProof",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "reportSha256": report["report_sha256"],
                    "claimBoundary": CLAIM_BOUNDARY,
                },
            }
        ],
    }
