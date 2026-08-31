"""SARIF export for AssuranceLedger ReReview."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.rereview import CLAIM_BOUNDARY, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceLedger ReReview report")
    rules = [
        {
            "id": "ALR001",
            "name": "rereview_required",
            "shortDescription": {"text": "A claim lost required trusted review"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ALR002",
            "name": "renewal_due",
            "shortDescription": {"text": "A claim relies on a historically trusted key"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ALR003",
            "name": "evidence_gap_unresolved",
            "shortDescription": {"text": "A valid evidence-gap statement remains unresolved"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ALR004",
            "name": "invalid_source_evidence",
            "shortDescription": {"text": "The source ledger report is invalid"},
            "help": {"text": CLAIM_BOUNDARY},
        },
    ]
    results = []
    mapping = {
        "rereview_required": ("ALR001", "error"),
        "renewal_due": ("ALR002", "warning"),
        "unresolved_evidence_gap": ("ALR003", "error"),
    }
    for item in report["claim_results"]:
        if item["status"] not in mapping:
            continue
        rule, level = mapping[item["status"]]
        results.append(
            {
                "ruleId": rule,
                "level": level,
                "message": {"text": f"{item['claim_id']}: {item['status'].replace('_', ' ')}."},
                "properties": {"missingRoles": item["missing_roles"], "automaticActions": 0},
            }
        )
    for error in report["source_errors"]:
        results.append(
            {
                "ruleId": "ALR004",
                "level": "error",
                "message": {"text": error},
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
                        "name": "DSPy Security Bench AssuranceLedger ReReview",
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
