"""Generic agent protocol + reference implementations.

Benchmark ANY tool-using agent for prompt-injection robustness, not just
dspy.ReActV2. Implement `Agent` (see base.py) or use a reference agent.
"""
from dspy_security_bench.agents.base import (
    Agent,
    AgentResult,
    AgentResultError,
    AgentToolExecutionError,
    BenchTool,
    ToolCall,
    apply_system_directive,
    validate_agent_result,
)
from dspy_security_bench.agents.usage import normalize_usage

__all__ = [
    "Agent",
    "AgentResult",
    "AgentResultError",
    "AgentToolExecutionError",
    "BenchTool",
    "ToolCall",
    "apply_system_directive",
    "validate_agent_result",
    "normalize_usage",
    "LiteLLMFunctionCallingAgent",
    "ToolBudgetAgent",
    "AgentToolBudgetError",
]


def __getattr__(name: str):
    """Keep protocol-only and offline tooling free of eager provider imports."""
    if name in {"ToolBudgetAgent", "AgentToolBudgetError"}:
        from dspy_security_bench.agents.budget import AgentToolBudgetError, ToolBudgetAgent

        return {"ToolBudgetAgent": ToolBudgetAgent, "AgentToolBudgetError": AgentToolBudgetError}[name]
    if name == "LiteLLMFunctionCallingAgent":
        from dspy_security_bench.agents.litellm_fc import LiteLLMFunctionCallingAgent

        return LiteLLMFunctionCallingAgent
    raise AttributeError(name)
