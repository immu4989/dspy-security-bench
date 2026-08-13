"""ImpactTwin procurement mission-assurance benchmark.

The benchmark runs clean and poisoned twins of the same procurement workflow,
then scores whether untrusted proposal text changed an economically material
decision or triggered a prohibited side effect.
"""

from dspy_security_bench.procurement.benchmark import (
    ImpactTwinReport,
    run_impact_twin,
)
from dspy_security_bench.procurement.evidence import (
    BoundaryEvent,
    CausalEvidence,
    RecommendedControl,
)
from dspy_security_bench.procurement.repeat import (
    RateEstimate,
    RepeatTwinReport,
    create_submission_bundle,
    run_repeat_twin,
    verify_submission_bundle,
)
from dspy_security_bench.proofrun import AttestationResult, capture_provenance

__all__ = [
    "BoundaryEvent",
    "AttestationResult",
    "CausalEvidence",
    "ImpactTwinReport",
    "RecommendedControl",
    "RateEstimate",
    "RepeatTwinReport",
    "create_submission_bundle",
    "capture_provenance",
    "run_impact_twin",
    "run_repeat_twin",
    "verify_submission_bundle",
]
