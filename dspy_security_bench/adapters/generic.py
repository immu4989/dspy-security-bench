"""Run ANY agent (satisfying `dspy_security_bench.agents.Agent`) inside an
AgentDojo evaluation pipeline.

This is the framework-agnostic sibling of `DSPyReActV2Element`. Where that
element drives a `dspy.ReActV2`, this one drives a user-supplied `Agent`:
LangChain, native function calling, CrewAI, MCP, a hand-rolled loop — anything.

The defense is applied across the same three channels, but two of them are now
enforced harness-side (so the agent cannot bypass them):

  - tool output  → we wrap each BenchTool's return value with the defense
  - query        → we pass the defense-rewritten query
  - instructions → we hand the agent a `system_directive` (the defense's
                   instruction-channel policy); the agent installs it as a
                   system prompt, or falls back to prepend-to-query.
"""
from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)

from dspy_security_bench.adapters.agentdojo import _serialize_result
from dspy_security_bench.agents.base import (
    Agent,
    AgentResultError,
    BenchTool,
    ToolCall,
    validate_agent_result,
)
from dspy_security_bench.agents.tools import _ToolSession


def _full_json_schema(function) -> dict:
    """Snapshot the runtime's argument schema without changing its semantics.

    References need their definitions; absent ``required`` does not mean all
    fields are required. Provider-specific adaptation belongs downstream, not
    in this framework-neutral handoff.
    """
    return deepcopy(function.parameters.model_json_schema())


def _make_bench_tool(function, runtime: FunctionsRuntime, env: Env, defense, user_query: str,
                     *, session: _ToolSession | None = None) -> BenchTool:
    """Wrap an AgentDojo Function as a BenchTool whose call executes for real
    and passes the observation through the active defense."""
    name = function.name
    desc = (function.description or "").strip()

    def execute(kwargs) -> str:
        result, error = runtime.run_function(env, name, kwargs, raise_on_error=False)
        output = _serialize_result(result, error)
        if defense is not None:
            output = defense.wrap_tool_output(output, tool_name=name, user_query=user_query)
        if not isinstance(output, str):
            raise AgentResultError("ToolCall.result must be text")
        return output

    def _call(**kwargs) -> str:
        return session.invoke(lambda: execute(kwargs)) if session is not None else execute(kwargs)

    return BenchTool(
        name=name,
        description=desc,
        parameters=_full_json_schema(function),
        _call=_call,
    )


class GenericAgentElement(BasePipelineElement):
    """Drives a user `Agent` inside an AgentDojo pipeline.

    Example:
        from dspy_security_bench.agents import LiteLLMFunctionCallingAgent
        from dspy_security_bench.adapters.generic import GenericAgentElement

        element = GenericAgentElement(
            LiteLLMFunctionCallingAgent("openai/gpt-4o-mini"),
            defense=get_defense("spotlight_delim"),
        )
        pipeline = AgentPipeline([InitQuery(), element])
    """

    name = "generic_agent"

    def __init__(self, agent: Agent, defense=None, max_tool_result_chars: int | None = None):
        self.agent = agent
        if defense is None:
            from dspy_security_bench.defenses import NoDefense
            defense = NoDefense()
        self.defense = defense
        self.max_tool_result_chars = max_tool_result_chars

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env | None = None,
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if env is None:
            env = EmptyEnv()
        if extra_args is None:
            extra_args = {}
        # Defense — query + instruction channels.
        defended_query = self.defense.rewrite_query(query)
        # The pure defense directive: apply rewrite_instructions to an empty
        # base so we get just the security policy the agent should install as a
        # system prompt (empty for NoDefense).
        system_directive = self.defense.rewrite_instructions("")

        # Defense — tool-output channel (harness-enforced).
        with _ToolSession() as session:
            tools = [
                _make_bench_tool(fn, runtime, env, self.defense, defended_query, session=session)
                for fn in runtime.functions.values()
            ]

            result = self.agent.run(defended_query, tools, system_directive=system_directive)
        result = validate_agent_result(result)
        session.validate()

        out_messages = list(messages)
        out_messages.extend(self._trace_to_messages(result.tool_calls))
        out_messages.append(ChatAssistantMessage(
            role="assistant",
            content=[text_content_block_from_string(result.final_answer)],
            tool_calls=None,
        ))

        return query, runtime, env, out_messages, extra_args

    def _trace_to_messages(self, tool_calls: list[ToolCall]) -> list[ChatMessage]:
        """Translate an agent's tool-call trace into AgentDojo ChatMessages."""
        msgs: list[ChatMessage] = []
        for i, tc in enumerate(tool_calls):
            call_id = f"call_{i}"
            msgs.append(ChatAssistantMessage(
                role="assistant",
                content=None,
                tool_calls=[FunctionCall(function=tc.name, args=tc.args, id=call_id)],
            ))
            result_text = tc.result
            if self.max_tool_result_chars and len(result_text) > self.max_tool_result_chars:
                result_text = result_text[: self.max_tool_result_chars] + "…[truncated]"
            msgs.append(ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string(result_text)],
                tool_call_id=call_id,
                tool_call=FunctionCall(function=tc.name, args=tc.args, id=call_id),
                error=None,
            ))
        return msgs
