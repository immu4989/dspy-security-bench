"""SARIF export for AssuranceLedger RootViewQuorum reports."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.root_view import CLAIM_BOUNDARY, REPORT_TYPE, TRUSTED_STATUS


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported RootViewQuorum report")
    summary = report["summary"]
    rules = [
        {
            "id": "ARV100",
            "name": "invalid_or_unanchored_root_view",
            "shortDescription": {"text": "Root-view evidence is invalid or not anchored"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ARV101",
            "name": "conflicting_or_newer_root_view",
            "shortDescription": {"text": "An observer reported conflicting root state"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "ARV102",
            "name": "insufficient_root_view_corroboration",
            "shortDescription": {"text": "Root-view quorum is not satisfied"},
            "help": {"text": CLAIM_BOUNDARY},
        },
    ]
    mapping = {
        "invalid_root_view_evidence": ("ARV100", "error"),
        "root_view_policy_not_pinned": ("ARV100", "error"),
        "root_view_request_mismatch": ("ARV100", "error"),
        "same_version_root_conflict": ("ARV101", "error"),
        "newer_root_reported": ("ARV101", "error"),
        "insufficient_root_observers": ("ARV102", "error"),
        "insufficient_root_observer_diversity": ("ARV102", "error"),
    }
    results = []
    if summary["status"] != TRUSTED_STATUS:
        rule, level = mapping.get(summary["status"], ("ARV100", "error"))
        results.append(
            {
                "ruleId": rule,
                "level": level,
                "message": {
                    "text": (
                        f"RootViewQuorum status {summary['status']}: "
                        f"{summary['matching_observers']} matching observers, "
                        f"{summary['newer_root_reports']} newer reports, and "
                        f"{summary['same_version_conflicts']} same-version conflicts."
                    )
                },
                "properties": {
                    "networkRequests": 0,
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
                        "name": "DSPy Security Bench RootViewQuorum",
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
