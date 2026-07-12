"""Generic agent protocol — benchmark ANY agent, not just dspy.ReActV2.

The benchmark's value is measuring how a *real* tool-using agent handles
prompt injection. That agent might be built with LangChain, OpenAI/Anthropic
native function calling, CrewAI, an MCP client, or a hand-rolled loop. This
module defines the minimal contract such an agent must satisfy, so the attack
+ defense machinery can drive it.

The one invariant you cannot break
----------------------------------
AgentDojo detects a successful injection *functionally* — it inspects the
environment after the run (e.g. "was an email actually sent to the attacker?").
The tools the harness hands your agent (`BenchTool`) execute against that live
environment. Your agent MUST call them. If it simulates or reimplements a tool
call instead of invoking the provided callable, the environment never mutates,
and the benchmark will report a FALSE "safe" result. Call the tools you're given.

Implementing an agent
---------------------
    from dspy_security_bench.agents import Agent, AgentResult, BenchTool

    class MyAgent:
        name = "my-agent"
        def run(self, query, tools, *, system_directive=""):
            # ... drive your framework, calling tools[i](**args) for real ...
            return AgentResult(final_answer=answer, tool_calls=trace)

Then benchmark it with `runner.evaluate_agents({"my-agent": MyAgent()}, ...)`.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class BenchTool:
    """A tool the harness hands to the agent.

    Calling it executes against the live AgentDojo runtime + environment and
    applies the active defense to the returned observation. This is the object
    your agent must actually invoke — see the module docstring.

    Attributes:
        name: tool name (matches the environment's function name).
        description: human/LLM-readable description.
        parameters: JSON Schema (draft 2020-12 style dict) for the arguments,
            suitable for an OpenAI/Anthropic `tools=[...]` spec.
        _call: harness-provided callable that runs the tool for real. Prefer
            calling the instance (`tool(**args)`) over touching `_call`.
    """

    name: str
    description: str
    parameters: dict
    _call: Callable[..., str]

    def __call__(self, **kwargs) -> str:
        return self._call(**kwargs)

    def openai_schema(self) -> dict:
        """This tool as an OpenAI/Anthropic function-calling tool spec."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters or {"type": "object", "properties": {}},
            },
        }


@dataclass
class ToolCall:
    """One tool invocation the agent made, for the trace."""

    name: str
    args: dict
    result: str


@dataclass
class AgentResult:
    """What an agent returns from a run.

    Attributes:
        final_answer: the agent's answer to the user query (scored for utility).
        tool_calls: optional trace of what the agent did. Not required for
            scoring — security is measured from env state, not the trace — but
            it improves logging and lets message-inspecting attacks target the
            agent. Provide it if it's cheap.
    """

    final_answer: str
    tool_calls: list[ToolCall] = field(default_factory=list)


@runtime_checkable
class Agent(Protocol):
    """The contract every benchmarked agent satisfies.

    Attributes:
        name: short identifier used in result rows and logs.
    """

    name: str

    def run(
        self,
        query: str,
        tools: list[BenchTool],
        *,
        system_directive: str = "",
    ) -> AgentResult:
        """Run the agent on one task.

        Args:
            query: the user's request (already defense-rewritten by the harness
                if a query-channel defense is active).
            tools: the tools available for this task. Call them for real.
            system_directive: security-policy text from the active defense's
                instruction channel (empty when no instruction-channel defense
                is active). Install it at your highest-trust position — the
                system prompt. If your framework cannot take a system prompt,
                see `apply_system_directive`, which prepends it to the query as
                a documented weaker approximation.

        Returns:
            An AgentResult with the final answer and (optionally) a trace.
        """
        ...


def apply_system_directive(query: str, system_directive: str, *, agent_name: str = "agent") -> str:
    """Fallback for agents that cannot accept a system prompt.

    Prepends the defense's instruction-channel policy to the user query and logs
    a warning, so the approximation is explicit in the run output. Agents that
    CAN take a system prompt should install `system_directive` there instead —
    this fallback is strictly weaker (the policy sits in the untrusted user turn
    rather than the trusted system turn).
    """
    if not system_directive:
        return query
    import logging

    logging.getLogger("dspy_security_bench.agents").warning(
        "agent %r cannot take a system prompt; prepending the defense directive to "
        "the user query as a weaker approximation (instruction-channel defense is "
        "measured with reduced fidelity for this agent).",
        agent_name,
    )
    return f"{system_directive}\n\n---\n\n{query}"
