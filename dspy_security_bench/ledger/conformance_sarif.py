"""SARIF export for AssuranceLedger verifier-conformance evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.conformance import CLAIM_BOUNDARY, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceLedger VerifierConformance report")
    results = [
        {
            "ruleId": "ALC001",
            "level": "error",
            "message": {
                "text": (
                    f"{item['case_id']}: the {item['artifact_kind']} verifier did not emit "
                    f"the required rejection {item['expected_error_fragment']!r}."
                )
            },
            "properties": {
                "artifactKind": item["artifact_kind"],
                "mutationSha256": item["mutation_sha256"],
                "verifierErrors": item["verifier_errors"],
                "automaticActions": 0,
            },
        }
        for item in report["cases"]
        if item["status"] == "unexpected_acceptance"
    ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench AssuranceLedger VerifierConformance",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": [
                            {
                                "id": "ALC001",
                                "name": "expected_adversarial_rejection_missing",
                                "shortDescription": {
                                    "text": "A native verifier missed its required adversarial rejection"
                                },
                                "help": {"text": CLAIM_BOUNDARY},
                            }
                        ],
                    }
                },
                "results": results,
                "properties": {
                    "reportSha256": report["report_sha256"],
                    "sourceArtifactSha256": report["source_artifact_sha256"],
                    "claimBoundary": CLAIM_BOUNDARY,
                },
            }
        ],
    }
