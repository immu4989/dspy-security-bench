"""TraceProof: privacy-bounded operational evidence for tool-using agents."""

from dspy_security_bench.trace.proof import (
    analyze_trace_evidence,
    build_trace_evidence,
    synthesize_trace_twin,
    verify_trace_artifact,
)

__all__ = [
    "analyze_trace_evidence",
    "build_trace_evidence",
    "synthesize_trace_twin",
    "verify_trace_artifact",
]
