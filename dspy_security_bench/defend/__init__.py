"""Verified cyber-defense remediation assurance."""

from dspy_security_bench.defend.protocol import (
    BUILT_IN_MISSIONS,
    analyze_remediation,
    built_in_mission,
    built_in_proposal,
    protocol_payload,
    protocol_sha256,
    validate_mission,
    validate_proposal,
    verify_report,
)

__all__ = [
    "BUILT_IN_MISSIONS",
    "analyze_remediation",
    "built_in_mission",
    "built_in_proposal",
    "protocol_payload",
    "protocol_sha256",
    "validate_mission",
    "validate_proposal",
    "verify_report",
]
