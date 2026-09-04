"""SARIF output for authenticated trust-recovery handoff findings."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.trust_recovery_attestation import CLAIM_BOUNDARY, REPORT_TYPE

_TOP_LEVEL_RULES = {
    "invalid_recovery_attestation_evidence": (
        "TRA100",
        "Recovery attestation inputs are invalid",
    ),
    "recovery_readiness_not_evidenced": (
        "TRA101",
        "The underlying recovery drill does not evidence readiness",
    ),
    "recovery_attestation_policy_not_authorized": (
        "TRA102",
        "The exact recovery-attestation policy is not authorized by the trust root",
    ),
    "untrusted_root": (
        "TRA103",
        "Recovery attestations are not rooted in the caller-selected trust anchor",
    ),
}


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported TrustRecoveryAttestation report")
    status = report["summary"]["status"]
    results = [
        {
            "ruleId": finding["rule_id"],
            "level": "error",
            "message": {"text": f"{finding['title']}: {finding['detail']}"},
            "properties": {
                "attestationIndexes": finding["attestation_indexes"],
                "automaticActions": 0,
            },
        }
        for finding in report["findings"]
        if finding["status"] == "failed"
    ]
    if status in _TOP_LEVEL_RULES:
        rule_id, title = _TOP_LEVEL_RULES[status]
        results.insert(
            0,
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": title},
                "properties": {"attestationIndexes": [], "automaticActions": 0},
            },
        )
    check_rules = [
        {
            "id": finding["rule_id"],
            "name": finding["title"],
            "shortDescription": {"text": finding["title"]},
            "help": {"text": CLAIM_BOUNDARY},
        }
        for finding in report["findings"]
    ]
    top_rules = [
        {
            "id": rule_id,
            "name": title,
            "shortDescription": {"text": title},
            "help": {"text": CLAIM_BOUNDARY},
        }
        for rule_id, title in _TOP_LEVEL_RULES.values()
    ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench TrustRecoveryAttestation",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": check_rules + top_rules,
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
