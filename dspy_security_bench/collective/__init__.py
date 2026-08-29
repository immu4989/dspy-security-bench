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
from dspy_security_bench.collective.v2 import (
    analyze_scenario_v2,
    built_in_scenario_v2,
)
from dspy_security_bench.collective.v2 import (
    verify_report as verify_collective_v2_report,
)

__all__ = [
    "BUILT_IN_PROFILES",
    "analyze_scenario",
    "built_in_scenario",
    "protocol_payload",
    "protocol_sha256",
    "validate_scenario",
    "verify_collective_report",
    "analyze_scenario_v2",
    "built_in_scenario_v2",
    "verify_collective_v2_report",
]
