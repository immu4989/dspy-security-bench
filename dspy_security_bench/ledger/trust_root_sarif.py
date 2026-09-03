"""SARIF output for AssuranceTrustRoot continuity and authorization findings."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.trust_root import CLAIM_BOUNDARY, REPORT_TYPE

_RULES = (
    ("ALTR001", "invalid_trust_evidence", "Trust-root evidence is structurally or cryptographically invalid"),
    ("ALTR002", "untrusted_bootstrap", "No independent bootstrap trust anchor was supplied"),
    ("ALTR003", "expired_trust_root", "The candidate trust root is expired"),
    ("ALTR004", "rollback_detected", "The candidate root version is not newer than trusted state"),
    ("ALTR005", "version_gap_detected", "One or more required intermediate roots are missing"),
    ("ALTR006", "trust_discontinuity", "The candidate fails predecessor continuity or threshold checks"),
    ("ALTR007", "policy_not_authorized", "An input policy digest is not authorized by the candidate root"),
)


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceTrustRoot report")
    status = report["summary"]["status"]
    mapping = {name: (rule_id, title) for rule_id, name, title in _RULES}
    results = []
    if status in mapping:
        rule_id, title = mapping[status]
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if status != "untrusted_bootstrap" else "warning",
                "message": {
                    "text": (
                        f"AssuranceTrustRoot status {status}: {title}. "
                        f"Candidate version {report['summary']['candidate_version']}; "
                        f"{report['summary']['unauthorized_policies']} unauthorized policies."
                    )
                },
                "properties": {
                    "rootSha256": report["candidate_root"].get("root_sha256"),
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
                        "name": "DSPy Security Bench AssuranceTrustRoot",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": name,
                                "shortDescription": {"text": title},
                                "help": {"text": CLAIM_BOUNDARY},
                            }
                            for rule_id, name, title in _RULES
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
