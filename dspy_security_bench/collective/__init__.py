"""CollectiveGuard: structural containment evidence for autonomous-agent collectives."""

from dspy_security_bench.collective.proof import (
    BUILT_IN_PROFILES,
    analyze_scenario,
    built_in_scenario,
    protocol_payload,
    protocol_sha256,
    validate_scenario,
    verify_collective_report,
)

__all__ = [
    "BUILT_IN_PROFILES",
    "analyze_scenario",
    "built_in_scenario",
    "protocol_payload",
    "protocol_sha256",
    "validate_scenario",
    "verify_collective_report",
]
