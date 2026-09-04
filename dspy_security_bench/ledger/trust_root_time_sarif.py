"""SARIF export for conservative TrustRootTimeGate reports."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.trust_root_time import (
    CLAIM_BOUNDARY,
    REPORT_TYPE,
    TRUSTED_STATUS,
)


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported TrustRootTimeGate report")
    summary = report["summary"]
    rules = [
        {
            "id": "ART100",
            "name": "invalid_or_unanchored_time",
            "shortDescription": {"text": "Time evidence is invalid or not caller-anchored"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ART101",
            "name": "time_quorum_not_satisfied",
            "shortDescription": {"text": "Bounded-time quorum cannot support evaluation"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ART102",
            "name": "root_not_valid_for_interval",
            "shortDescription": {"text": "Root is not trusted across the entire interval"},
            "help": {"text": CLAIM_BOUNDARY},
        },
    ]
    mapping = {
        "invalid_time_quorum": ("ART100", "error"),
        "time_policy_not_pinned": ("ART100", "error"),
        "time_request_mismatch": ("ART100", "error"),
        "time_subject_mismatch": ("ART100", "error"),
        "time_quorum_not_satisfied": ("ART101", "error"),
        "time_interval_unavailable": ("ART101", "error"),
        "root_not_yet_valid_for_interval": ("ART102", "error"),
        "root_expires_within_interval": ("ART102", "error"),
        "root_trust_failed": ("ART102", "error"),
    }
    results = []
    if summary["status"] != TRUSTED_STATUS:
        rule, level = mapping.get(summary["status"], ("ART102", "error"))
        results.append(
            {
                "ruleId": rule,
                "level": level,
                "message": {
                    "text": (
                        f"TrustRootTimeGate status {summary['status']}: interval "
                        f"[{summary['lower_bound_unix']}, {summary['upper_bound_unix']}], "
                        f"root statuses {summary['lower_bound_root_status']} / "
                        f"{summary['upper_bound_root_status']}."
                    )
                },
                "properties": {
                    "clockAdjustments": 0,
                    "rootsInstalled": 0,
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
                        "name": "DSPy Security Bench TrustRootTimeGate",
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
