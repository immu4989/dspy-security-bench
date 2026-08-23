"""AuthorityTwin agent-identity and delegated-authorization conformance lab."""

from dspy_security_bench.authority.adapter import AuthorityAdapter, AuthorityDecision
from dspy_security_bench.authority.benchmark import (
    AuthorityTwinReport,
    run_authority_twin,
    verify_authority_report,
)
from dspy_security_bench.authority.bridges import (
    AUTHORITY_BRIDGES,
    PolicyEngineAuthorityBridge,
)
from dspy_security_bench.authority.protocol import protocol_sha256

__all__ = [
    "AuthorityAdapter",
    "AuthorityDecision",
    "AuthorityTwinReport",
    "AUTHORITY_BRIDGES",
    "PolicyEngineAuthorityBridge",
    "protocol_sha256",
    "run_authority_twin",
    "verify_authority_report",
]
