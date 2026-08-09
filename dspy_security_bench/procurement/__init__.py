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

__all__ = [
    "BoundaryEvent",
    "CausalEvidence",
    "ImpactTwinReport",
    "RecommendedControl",
    "run_impact_twin",
]
