"""Cooperative, per-task admission limits on harness-supplied tool calls.

This is not a sandbox, cancellation mechanism, token budget, or control over
network/tool access that an agent creates outside its supplied BenchTools.
"""

from __future__ import annotations

from copy import deepcopy
from threading import Lock

from dspy_security_bench.agents.base import Agent, AgentResult, BenchTool

TOOL_BUDGET_PROTOCOL = "tool-budgeted-binary-observations-v3"
MAX_TOOL_CALLS = 10_000


class AgentToolBudgetError(RuntimeError):
    """Tool admission or task lifecycle was incomplete; not a measured safe result."""


class ToolBudgetAgent:
    """Limit supplied-tool invocations for each call to an existing agent's run.

    Each attempted invocation of a wrapped tool consumes one admission before
    its callback starts, including callbacks that raise. Calls beyond the limit
    never reach the original tool. Counts are local to a run and lock-protected
    for cooperative thread-based parallel tool use. Exhaustion remains visible
    even if the wrapped agent catches the immediate tool error.
    """

    def __init__(self, agent: Agent, max_tool_calls_per_task: int):
        if type(max_tool_calls_per_task) is not int or not 1 <= max_tool_calls_per_task <= MAX_TOOL_CALLS:
            raise ValueError("tool-call budget must be an integer from 1 to 10000")
        self.agent = agent
        self.name = agent.name
        self.max_tool_calls_per_task = max_tool_calls_per_task

    def run(self, query: str, tools: list[BenchTool], *, system_directive: str = "") -> AgentResult:
        limit = self.max_tool_calls_per_task
        if type(limit) is not int or not 1 <= limit <= MAX_TOOL_CALLS:
            raise ValueError("tool-call budget must remain an integer from 1 to 10000")
        lock = Lock()
        admitted, active = 0, 0
        exhausted, closed = False, False

        def wrap(tool: BenchTool) -> BenchTool:
            def call(**kwargs):
                nonlocal admitted, active, exhausted
                with lock:
                    if closed:
                        raise AgentToolBudgetError("tool session is closed; callback was not executed")
                    if admitted >= limit:
                        exhausted = True
                        raise AgentToolBudgetError("per-task tool-call budget exceeded; callback was not executed")
                    admitted += 1
                    active += 1
                try:
                    return tool(**kwargs)
                finally:
                    with lock:
                        active -= 1

            return BenchTool(tool.name, tool.description, deepcopy(tool.parameters), call)

        wrapped = [wrap(tool) for tool in tools]
        try:
            result = self.agent.run(query, wrapped, system_directive=system_directive)
        finally:
            with lock:
                closed = True
                incomplete = active > 0
        if incomplete:
            raise AgentToolBudgetError("agent returned with tool callbacks still running; no complete measurement")
        if exhausted:
            raise AgentToolBudgetError("agent exceeded the per-task tool budget; no complete measurement")
        return result
