"""SARIF export for compact AssuranceLedger consistency proofs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.consistency import CLAIM_BOUNDARY, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceLedger ConsistencyProof report")
    finding = report["finding"]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench AssuranceLedger ConsistencyProof",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": [
                            {
                                "id": "ALC001",
                                "name": "append_only_extension_proved",
                                "shortDescription": {
                                    "text": "A newer signed checkpoint preserves the older tree"
                                },
                                "help": {"text": CLAIM_BOUNDARY},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "ALC001",
                        "level": "note",
                        "message": {
                            "text": (
                                f"Append-only extension proved for {finding['log_origin']} "
                                f"with {finding['path_node_count']} compact Merkle nodes."
                            )
                        },
                        "properties": {
                            "olderRootSha256": finding["older_root_sha256"],
                            "newerRootSha256": finding["newer_root_sha256"],
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
