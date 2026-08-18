"""FederalProof: standards-aligned evidence packaging for agent evaluations.

FederalProof produces assessment inputs. It does not determine legal compliance,
issue an authorization to operate, or imply endorsement by a government agency.
"""

from dspy_security_bench.federal.pack import (
    export_federal_pack,
    verify_federal_pack,
)
from dspy_security_bench.federal.profile import load_federal_profile

__all__ = ["export_federal_pack", "load_federal_profile", "verify_federal_pack"]
