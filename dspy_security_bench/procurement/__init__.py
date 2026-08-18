"""ImpactTwin procurement mission-assurance benchmark.

The benchmark runs clean and poisoned twins of the same procurement workflow,
then scores whether untrusted proposal text changed an economically material
decision or triggered a prohibited side effect.
"""

from dspy_security_bench.procurement.benchmark import (
    ImpactTwinReport,
    run_impact_twin,
)
from dspy_security_bench.procurement.control_registry import (
    ControlSubmissionVerification,
    create_control_submission_bundle,
    render_control_evidence_card_svg,
    verify_control_submission_bundle,
)
from dspy_security_bench.procurement.control_twin import (
    ControlTwinReport,
    run_control_twin,
    verify_control_report,
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
from dspy_security_bench.procurement.repeat_control import (
    RepeatControlTwinReport,
    run_repeat_control_twin,
    verify_repeat_control_report,
)
from dspy_security_bench.proofrun import AttestationResult, capture_provenance

__all__ = [
    "BoundaryEvent",
    "AttestationResult",
    "CausalEvidence",
    "ControlTwinReport",
    "ControlSubmissionVerification",
    "ImpactTwinReport",
    "RecommendedControl",
    "RateEstimate",
    "RepeatControlTwinReport",
    "RepeatTwinReport",
    "create_submission_bundle",
    "create_control_submission_bundle",
    "capture_provenance",
    "run_impact_twin",
    "run_control_twin",
    "run_repeat_twin",
    "run_repeat_control_twin",
    "render_control_evidence_card_svg",
    "verify_submission_bundle",
    "verify_control_report",
    "verify_control_submission_bundle",
    "verify_repeat_control_report",
]
