"""SARIF export for compact AssuranceLedger fork proofs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.misbehavior import CLAIM_BOUNDARY, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceLedger ForkProof report")
    finding = report["finding"]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench AssuranceLedger ForkProof",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": [
                            {
                                "id": "ALF001",
                                "name": "operator_equivocation_proved",
                                "shortDescription": {
                                    "text": "One operator signed different roots at the same tree size"
                                },
                                "help": {"text": CLAIM_BOUNDARY},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "ALF001",
                        "level": "error",
                        "message": {
                            "text": (
                                f"Operator equivocation is cryptographically proved for "
                                f"{finding['log_origin']} at tree size {finding['tree_size']}."
                            )
                        },
                        "properties": {
                            "leftRootSha256": finding["left_root_sha256"],
                            "rightRootSha256": finding["right_root_sha256"],
                            "automaticActions": 0,
                        },
                    }
                ],
                "properties": {
                    "reportSha256": report["report_sha256"],
                    "claimBoundary": CLAIM_BOUNDARY,
                },
            }
        ],
    }
