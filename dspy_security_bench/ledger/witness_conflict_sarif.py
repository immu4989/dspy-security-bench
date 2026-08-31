"""SARIF export for AssuranceLedger witness-conflict attribution."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.witness_conflict import CLAIM_BOUNDARY, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceLedger WitnessConflict report")
    results = [
        {
            "ruleId": "ALW001",
            "level": "error",
            "message": {
                "text": (
                    f"Witness key {item['public_key_sha256']} ({item['witness_id']}) "
                    "signed both conflicting same-size checkpoints."
                )
            },
            "properties": {
                "organizationId": item["organization_id"],
                "automaticActions": 0,
            },
        }
        for item in report["witness_results"]
        if item["status"] == "signed_both_conflicting_checkpoints"
    ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench AssuranceLedger WitnessConflict",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": [
                            {
                                "id": "ALW001",
                                "name": "witness_signed_both_fork_views",
                                "shortDescription": {
                                    "text": "One witness key signed conflicting checkpoints"
                                },
                                "help": {"text": CLAIM_BOUNDARY},
                            }
                        ],
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
