"""SARIF export for EvalIntegrityProof."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.evalguard.proof import CLAIM_BOUNDARY, CONTROLS, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported EvalIntegrityProof report")
    rules = [
        {
            "id": control_id,
            "name": definition["category"].replace("-", "_"),
            "shortDescription": {"text": definition["title"]},
            "help": {"text": CLAIM_BOUNDARY},
        }
        for control_id, definition in CONTROLS.items()
    ]
    results = []
    for item in report["control_results"]:
        if item["status"] == "evidenced":
            continue
        results.append(
            {
                "ruleId": item["control_id"],
                "level": "error" if item["status"] == "violation_observed" else "warning",
                "message": {"text": f"{item['title']}: {item['finding']}."},
                "properties": {
                    "integrityStatus": item["status"],
                    "sourceIds": item["source_ids"],
                    "evidencePaths": item["evidence_paths"],
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
                        "name": "DSPy Security Bench EvalIntegrityProof",
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
