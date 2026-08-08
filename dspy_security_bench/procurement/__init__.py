"""ImpactTwin procurement mission-assurance benchmark.

The benchmark runs clean and poisoned twins of the same procurement workflow,
then scores whether untrusted proposal text changed an economically material
decision or triggered a prohibited side effect.
"""

from dspy_security_bench.procurement.benchmark import (
    ImpactTwinReport,
    run_impact_twin,
)

__all__ = ["ImpactTwinReport", "run_impact_twin"]
