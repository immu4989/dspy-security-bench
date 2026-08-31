"""SARIF export for AssuranceLedger cross-view gossip."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.gossip import CLAIM_BOUNDARY, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceLedger Gossip report")
    rules = [
        {
            "id": "ALG001",
            "name": "equivocation_evidenced",
            "shortDescription": {"text": "Valid operator-signed log views fork"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ALG002",
            "name": "invalid_view_evidence",
            "shortDescription": {"text": "A supplied ledger view is invalid"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ALG003",
            "name": "insufficient_view_diversity",
            "shortDescription": {"text": "No distinct checkpoint was available to compare"},
            "help": {"text": CLAIM_BOUNDARY},
        },
    ]
    results = []
    for item in report["comparisons"]:
        if item["status"] == "equivocation_evidenced":
            results.append(
                {
                    "ruleId": "ALG001",
                    "level": "error",
                    "message": {"text": item["reason"]},
                    "properties": {
                        "leftView": item["left_view_index"],
                        "rightView": item["right_view_index"],
                        "automaticActions": 0,
                    },
                }
            )
    for item in report["view_results"]:
        if item["status"] == "invalid":
            results.append(
                {
                    "ruleId": "ALG002",
                    "level": "error",
                    "message": {"text": f"View {item['view_index']}: {'; '.join(item['errors'])}."},
                    "properties": {"automaticActions": 0},
                }
            )
    if report["summary"]["status"] == "insufficient_view_diversity":
        results.append(
            {
                "ruleId": "ALG003",
                "level": "warning",
                "message": {
                    "text": "At least two distinct checkpoints are required for a cross-view comparison."
                },
                "properties": {"automaticActions": 0},
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench AssuranceLedger Gossip",
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
