"""SARIF output for AssuranceTrustRootChain findings."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dspy_security_bench.ledger.trust_chain import CLAIM_BOUNDARY, REPORT_TYPE

_RULES = (
    ("ALTC001", "invalid_chain_evidence", "One or more supplied roots are invalid"),
    ("ALTC002", "untrusted_bootstrap", "No independent bootstrap trust anchor was supplied"),
    ("ALTC003", "expired_final_root", "The final trust root is expired"),
    ("ALTC004", "not_yet_valid_final_root", "The final trust root is not yet valid"),
    ("ALTC005", "rollback_detected", "The chain contains a rollback"),
    ("ALTC006", "version_gap_detected", "The chain omits an exact successor version"),
    ("ALTC007", "trust_discontinuity", "A root transition fails continuity or threshold checks"),
    ("ALTC008", "final_version_not_reached", "The final root is below the required version"),
    ("ALTC009", "policy_not_authorized", "A policy is not authorized by the final root"),
)


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceTrustRootChain report")
    status = report["summary"]["status"]
    mapping = {name: (rule_id, title) for rule_id, name, title in _RULES}
    results = []
    if status in mapping:
        rule_id, title = mapping[status]
        results.append(
            {
                "ruleId": rule_id,
                "level": "warning" if status == "untrusted_bootstrap" else "error",
                "message": {
                    "text": (
                        f"AssuranceTrustRootChain status {status}: {title}. "
                        f"Verified {report['summary']['transitions_verified']} of "
                        f"{report['summary']['transitions_required']} required transitions."
                    )
                },
                "properties": {
                    "finalRootSha256": report["root_inputs"][-1].get("root_sha256"),
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
                        "name": "DSPy Security Bench AssuranceTrustRootChain",
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
