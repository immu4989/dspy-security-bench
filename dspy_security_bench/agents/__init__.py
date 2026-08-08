"""Generic agent protocol + reference implementations.

Benchmark ANY tool-using agent for prompt-injection robustness, not just
dspy.ReActV2. Implement `Agent` (see base.py) or use a reference agent.
"""
from dspy_security_bench.agents.base import (
    Agent,
    AgentResult,
    BenchTool,
    ToolCall,
    apply_system_directive,
)

__all__ = [
    "Agent",
    "AgentResult",
    "BenchTool",
    "ToolCall",
    "apply_system_directive",
    "LiteLLMFunctionCallingAgent",
]


def __getattr__(name: str):
    """Keep protocol-only and offline tooling free of eager provider imports."""
    if name == "LiteLLMFunctionCallingAgent":
        from dspy_security_bench.agents.litellm_fc import LiteLLMFunctionCallingAgent

        return LiteLLMFunctionCallingAgent
    raise AttributeError(name)
