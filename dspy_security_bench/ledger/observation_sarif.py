"""SARIF export for AssuranceLedger observer-receipt analysis."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.observation import CLAIM_BOUNDARY, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceLedger ObserverReceipt report")
    summary = report["summary"]
    rules = [
        {
            "id": "ALO001",
            "name": "independently_observed_equivocation",
            "shortDescription": {"text": "Independent receipts bind a same-size fork"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ALO002",
            "name": "invalid_observation_evidence",
            "shortDescription": {"text": "An observer receipt or policy is invalid"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ALO003",
            "name": "insufficient_observer_independence",
            "shortDescription": {"text": "Observer independence threshold is unmet"},
            "help": {"text": CLAIM_BOUNDARY},
        },
    ]
    mapping = {
        "independently_observed_equivocation": ("ALO001", "error"),
        "invalid_observation_evidence": ("ALO002", "error"),
        "insufficient_observer_independence": ("ALO003", "warning"),
    }
    results = []
    if summary["status"] in mapping:
        rule, level = mapping[summary["status"]]
        results.append(
            {
                "ruleId": rule,
                "level": level,
                "message": {
                    "text": f"ObserverReceipt status {summary['status']}: {summary['valid_receipts']} valid receipts, {summary['distinct_organizations']} organizations, {summary['distinct_channels']} channels."
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
                        "name": "DSPy Security Bench AssuranceLedger ObserverReceipt",
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
