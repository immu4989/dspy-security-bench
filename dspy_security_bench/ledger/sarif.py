"""SARIF export for AssuranceLedger."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.proof import CLAIM_BOUNDARY, REPORT_TYPE


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceLedger report")
    rules = [
        {
            "id": "AL001",
            "name": "reviewer_trust_invalidated",
            "shortDescription": {"text": "A logged compromise invalidates review trust"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "AL002",
            "name": "trust_evidence_incomplete",
            "shortDescription": {"text": "Reviewer lifecycle or inclusion evidence is incomplete"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "AL003",
            "name": "invalid_ledger_evidence",
            "shortDescription": {"text": "Checkpoint, witness, source, or log evidence is invalid"},
            "help": {"text": CLAIM_BOUNDARY},
        },
        {
            "id": "AL004",
            "name": "reviewer_trust_historical",
            "shortDescription": {"text": "A historically valid review key is now retired"},
            "help": {"text": CLAIM_BOUNDARY},
        },
    ]
    results = []
    status_to_rule = {
        "reviewer_trust_invalidated": ("AL001", "error"),
        "trust_evidence_incomplete": ("AL002", "warning"),
        "reviewer_trust_historical": ("AL004", "note"),
    }
    for item in report["review_results"]:
        if item["status"] not in status_to_rule:
            continue
        rule, level = status_to_rule[item["status"]]
        results.append(
            {
                "ruleId": rule,
                "level": level,
                "message": {"text": f"{item['signer_id']}: {item['status'].replace('_', ' ')}."},
                "properties": {
                    "envelopeSha256": item["envelope_sha256"],
                    "revocationEvents": item["revocation_event_sha256s"],
                    "automaticActions": 0,
                },
            }
        )
    for error in [*report["source_errors"], *report["checkpoint_errors"]]:
        results.append(
            {
                "ruleId": "AL003",
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
                        "name": "DSPy Security Bench AssuranceLedger",
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
