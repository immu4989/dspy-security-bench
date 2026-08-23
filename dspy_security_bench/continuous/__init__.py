"""ContinuousProof evidence baselines and deterministic drift comparisons."""

from dspy_security_bench.continuous.proof import (
    build_evidence_snapshot,
    compare_evidence,
    verify_continuous_proof,
)

__all__ = ["build_evidence_snapshot", "compare_evidence", "verify_continuous_proof"]
