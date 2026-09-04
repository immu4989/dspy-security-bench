"""SARIF export for AssuranceTimeQuorum reports."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.time_quorum import CLAIM_BOUNDARY, REPORT_TYPE, TRUSTED_STATUS


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceTimeQuorum report")
    summary = report["summary"]
    rules = [
        {
            "id": "ATQ100",
            "name": "invalid_time_evidence",
            "shortDescription": {"text": "A time policy, receipt, or signature is invalid"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ATQ101",
            "name": "time_request_not_anchored",
            "shortDescription": {"text": "The policy pin or request binding is not satisfied"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ATQ102",
            "name": "insufficient_time_source_quorum",
            "shortDescription": {"text": "Source or organization diversity is insufficient"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ATQ103",
            "name": "inconsistent_or_wide_time_interval",
            "shortDescription": {"text": "Signed intervals do not yield an acceptable overlap"},
            "help": {"text": CLAIM_BOUNDARY},
        },
    ]
    status = summary["status"]
    mapping = {
        "invalid_time_evidence": ("ATQ100", "error"),
        "time_policy_not_pinned": ("ATQ101", "error"),
        "time_request_mismatch": ("ATQ101", "error"),
        "insufficient_time_sources": ("ATQ102", "warning"),
        "insufficient_time_source_diversity": ("ATQ102", "warning"),
        "time_sources_inconsistent": ("ATQ103", "error"),
        "time_uncertainty_too_wide": ("ATQ103", "warning"),
    }
    results = []
    if status != TRUSTED_STATUS:
        rule, level = mapping.get(status, ("ATQ100", "error"))
        interval = report["conservative_interval"]
        results.append(
            {
                "ruleId": rule,
                "level": level,
                "message": {
                    "text": (
                        f"AssuranceTimeQuorum status {status}: "
                        f"{summary['valid_receipts']} valid receipts from "
                        f"{summary['distinct_organizations']} organizations; "
                        f"conservative width {interval['width_seconds']}."
                    )
                },
                "properties": {
                    "clockAdjustments": 0,
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
                        "name": "DSPy Security Bench AssuranceTimeQuorum",
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
