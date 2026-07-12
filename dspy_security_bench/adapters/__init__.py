"""Adapters that let agents run inside external evaluation frameworks."""
from dspy_security_bench.adapters.agentdojo import DSPyReActV2Element
from dspy_security_bench.adapters.generic import GenericAgentElement

__all__ = ["DSPyReActV2Element", "GenericAgentElement"]
