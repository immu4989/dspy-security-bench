"""SARIF export for AssuranceQuorum."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.quorum.proof import CLAIM_BOUNDARY, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceQuorum report")
    rules = [
        {
            "id": "AQ001",
            "name": "review_gap_recorded",
            "shortDescription": {"text": "An authorized reviewer recorded an evidence gap"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "AQ002",
            "name": "quorum_incomplete",
            "shortDescription": {"text": "Required role or organization review is incomplete"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "AQ003",
            "name": "invalid_review_evidence",
            "shortDescription": {
                "text": "Review signature, subject, authorization, or freshness is invalid"
            },
            "help": {"text": CLAIM_BOUNDARY},
        },
    ]
    results = []
    for item in report["claim_results"]:
        if item["status"] == "quorum_satisfied":
            continue
        rule_id = "AQ001" if item["status"] == "review_gap_recorded" else "AQ002"
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if rule_id == "AQ001" else "warning",
                "message": {"text": f"{item['claim_id']}: {item['status'].replace('_', ' ')}."},
                "properties": {
                    "gapReviewers": item["gap_reviewers"],
                    "missingRoles": item["missing_roles"],
                    "automaticActions": 0,
                },
            }
        )
    for item in report["review_results"]:
        if item["status"] == "invalid":
            results.append(
                {
                    "ruleId": "AQ003",
                    "level": "error",
                    "message": {
                        "text": f"Review {item['review_index']} is invalid: {'; '.join(item['errors'])}."
                    },
                    "properties": {
                        "envelopeSha256": item["envelope_sha256"],
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
                        "name": "DSPy Security Bench AssuranceQuorum",
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
