"""SARIF export for AssuranceLedger IntegrationLock drift evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.integration_lock import (
    CHECK_REPORT_TYPE,
    CLAIM_BOUNDARY,
)

RULES = {
    "invalid-lock": ("AIL001", "invalid_integration_lock", "The owner lock is invalid"),
    "invalid-candidate": (
        "AIL002",
        "invalid_candidate_manifest",
        "The candidate capability manifest is invalid",
    ),
    "schema-drift": ("AIL003", "pinned_schema_drift", "A pinned schema digest changed"),
    "missing-protocol": ("AIL004", "required_protocol_missing", "A pinned protocol is missing"),
    "protocol-contract-drift": (
        "AIL005",
        "pinned_protocol_contract_drift",
        "A pinned protocol contract changed",
    ),
}


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != CHECK_REPORT_TYPE:
        raise ValueError("unsupported AssuranceLedger IntegrationLockCheck report")
    rules = [
        {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": description},
            "help": {"text": CLAIM_BOUNDARY},
        }
        for rule_id, name, description in RULES.values()
    ]
    results = []
    for finding in report["findings"]:
        rule_id = RULES[finding["rule_id"]][0]
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": f"{finding['subject']}: {finding['detail']}"},
                "properties": {
                    "findingKind": finding["rule_id"],
                    "subject": finding["subject"],
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
                        "name": "DSPy Security Bench AssuranceLedger IntegrationLock",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "reportSha256": report["report_sha256"],
                    "lockSha256": report["lock_sha256"],
                    "candidateManifestSha256": report["candidate_manifest_sha256"],
                    "claimBoundary": CLAIM_BOUNDARY,
                },
            }
        ],
    }
