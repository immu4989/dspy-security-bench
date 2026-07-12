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
from dspy_security_bench.agents.litellm_fc import LiteLLMFunctionCallingAgent

__all__ = [
    "Agent",
    "AgentResult",
    "BenchTool",
    "ToolCall",
    "apply_system_directive",
    "LiteLLMFunctionCallingAgent",
]
