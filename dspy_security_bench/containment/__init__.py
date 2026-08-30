"""ContainmentProof public API."""

from dspy_security_bench.containment.proof import (
    analyze_scenario,
    built_in_scenario,
    protocol_payload,
    protocol_sha256,
    seal_scenario,
    verify_report,
)

__all__ = [
    "analyze_scenario",
    "built_in_scenario",
    "protocol_payload",
    "protocol_sha256",
    "seal_scenario",
    "verify_report",
]
