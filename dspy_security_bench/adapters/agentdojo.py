"""Run a dspy.ReActV2 program inside an AgentDojo evaluation pipeline.

This is the bridge that lets us measure DSPy programs against AgentDojo's
attack suites. Attacks plant adversarial content in the env; since our DSPy
tools call back into `runtime.run_function(env, ...)`, the malicious content
flows naturally into tool outputs and exercises the agent's robustness.

Key v0.1 constraints (documented for honest scope):

1. The DSPy signature passed to the wrapped agent must have **exactly one
   output field**. We surface that field's value as the AgentDojo
   `model_output` string. Multi-output signatures aren't yet supported.

2. Tool results are JSON-serialized (via `_serialize_result`) before being
   handed to the agent. Complex Pydantic objects flatten via `model_dump()`.
   Lossy in principle but defensible because LLMs read structured tool
   outputs as text either way.

3. Errors from `runtime.run_function` surface as observation strings, not as
   raised exceptions. ReActV2 sees them as normal tool output and decides
   what to do.

4. The ReActV2 ID-collision bug (issue #9825) is irrelevant here because each
   AgentDojo task is a single `forward()` call.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

import dspy
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize_result(result: Any, error: str | None) -> str:
    """Turn a runtime.run_function return value into an observation string."""
    if error is not None:
        return f"[error] {error}"
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    if isinstance(result, (int, float, bool)):
        return str(result)
    # Pydantic model
    if hasattr(result, "model_dump"):
        try:
            return json.dumps(result.model_dump(), default=str)
        except Exception:
            return str(result)
    # List/sequence of pydantic models, dicts, or primitives
    if isinstance(result, (list, tuple)):
        items = []
        for it in result:
            if hasattr(it, "model_dump"):
                items.append(it.model_dump())
            else:
                items.append(it)
        try:
            return json.dumps(items, default=str)
        except Exception:
            return str(items)
    if isinstance(result, dict):
        try:
            return json.dumps(result, default=str)
        except Exception:
            return str(result)
    return str(result)


def _build_tool_args_schema(function) -> dict:
    """Extract a JSON-schema-shaped args dict from an AgentDojo Function.

    Returns a dict keyed by parameter name with each value being the
    JSON schema for that parameter. This is what dspy.Tool wants.
    """
    params_model = function.parameters
    schema = params_model.model_json_schema()
    properties = schema.get("properties", {})
    return {name: properties.get(name, {"type": "string"}) for name in params_model.model_fields}


def _build_tool_arg_types(function) -> dict:
    """Extract Python type annotations for each parameter."""
    params_model = function.parameters
    arg_types = {}
    for name, field_info in params_model.model_fields.items():
        arg_types[name] = field_info.annotation
    return arg_types


def _make_dspy_tool(
    function,
    runtime: FunctionsRuntime,
    env: Env,
) -> dspy.Tool:
    """Wrap an AgentDojo `Function` as a dspy.Tool that calls back into the runtime."""
    name = function.name
    desc = (function.description or "").strip()
    args_schema = _build_tool_args_schema(function)
    arg_types = _build_tool_arg_types(function)

    def tool_fn(**kwargs):
        result, error = runtime.run_function(env, name, kwargs, raise_on_error=False)
        return _serialize_result(result, error)

    tool_fn.__name__ = name
    tool_fn.__doc__ = desc

    return dspy.Tool(
        tool_fn,
        name=name,
        desc=desc,
        args=args_schema,
        arg_types=arg_types,
    )


def _tool_call_to_function_call(tc) -> FunctionCall:
    """Translate ReActV2's ToolCalls.ToolCall → AgentDojo FunctionCall."""
    return FunctionCall(
        function=tc.name,
        args=tc.args or {},
        id=tc.id,
    )


def _event_to_chat_messages(event: dict) -> list[ChatMessage]:
    """ReActV2 history event → AgentDojo (ChatAssistantMessage, ChatToolResultMessages...).

    A ReActV2 event represents one trajectory step: an assistant turn that
    proposed tool_calls and the tool results that came back. We emit:
      - One ChatAssistantMessage with the next_thought and tool_calls
      - One ChatToolResultMessage per tool call result
    """
    msgs: list[ChatMessage] = []

    next_thought = event.get("next_thought")
    tcs = event.get("tool_calls")
    if tcs is None or not getattr(tcs, "tool_calls", None):
        # Plain text turn (no tools called) — emit just the thought if any
        if next_thought:
            msgs.append(ChatAssistantMessage(
                role="assistant",
                content=[text_content_block_from_string(str(next_thought))],
                tool_calls=None,
            ))
        return msgs

    function_calls = [_tool_call_to_function_call(tc) for tc in tcs.tool_calls]
    assistant_content = (
        [text_content_block_from_string(str(next_thought))]
        if next_thought else None
    )
    msgs.append(ChatAssistantMessage(
        role="assistant",
        content=assistant_content,
        tool_calls=function_calls,
    ))

    # Tool results
    results_obj = getattr(tcs, "tool_call_results", None)
    if results_obj is not None:
        results_list = results_obj.tool_call_results
        # Build a lookup by call_id so we can match results to calls
        result_by_call_id = {r.call_id: r for r in results_list}
        for fc in function_calls:
            r = result_by_call_id.get(fc.id)
            if r is None:
                continue
            value = r.value if hasattr(r, "value") else r
            is_error = getattr(r, "is_error", False)
            content_str = _serialize_result(value, None) if not is_error else ""
            error_str = _serialize_result(value, None) if is_error else None
            msgs.append(ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string(content_str)],
                tool_call=fc,
                tool_call_id=fc.id,
                error=error_str,
            ))
    return msgs


# ---------------------------------------------------------------------------
# Pipeline element
# ---------------------------------------------------------------------------

class DSPyReActV2Element(BasePipelineElement):
    """Runs a (possibly pre-optimized) dspy.ReActV2 inside an AgentDojo pipeline.

    The optimization step happens OUTSIDE this element — the caller passes
    an `agent_factory` that returns a configured `dspy.ReActV2` instance
    (without tools — tools are injected here, bound to AgentDojo's runtime+env).

    The factory signature is:
        agent_factory(tools: list[dspy.Tool], max_iters: int) -> dspy.ReActV2

    Example:
        def make_agent(tools, max_iters):
            return dspy.ReActV2(
                signature="query -> answer",
                tools=tools,
                max_iters=max_iters,
            )

        pipeline = AgentPipeline([
            ... # SystemMessage, InitQuery, etc.
            DSPyReActV2Element(make_agent),
        ])
    """

    name = "dspy_reactv2"

    def __init__(
        self,
        agent_factory: Callable[..., Any],
        max_iters: int = 20,
        output_field: str | None = None,
    ):
        """
        Args:
            agent_factory: callable that returns a dspy.ReActV2 given
                (tools=..., max_iters=...) keyword args.
            max_iters: Cap on ReActV2 iterations per task.
            output_field: Name of the signature's single output field. If None,
                inferred from the agent's signature at runtime (must be a
                signature with exactly one output).
        """
        self.agent_factory = agent_factory
        self.max_iters = max_iters
        self.output_field = output_field

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        # 1) Bind AgentDojo tools as dspy.Tool closures
        tools = [_make_dspy_tool(fn, runtime, env) for fn in runtime.functions.values()]

        # 2) Instantiate the agent with these tools
        agent = self.agent_factory(tools=tools, max_iters=self.max_iters)

        # 3) Determine the output field name
        output_field = self.output_field
        if output_field is None:
            output_fields = list(agent.signature.output_fields.keys())
            if len(output_fields) != 1:
                raise ValueError(
                    f"DSPyReActV2Element v0.1 requires a single output field; "
                    f"got {output_fields}. Pass output_field=... explicitly."
                )
            output_field = output_fields[0]

        # 4) Run the agent
        agent_result = agent(query=query)

        # 5) Translate trajectory → AgentDojo ChatMessages
        out_messages = list(messages)
        for event in agent_result.history.messages:
            out_messages.extend(_event_to_chat_messages(event))

        # 6) Emit final assistant message with the answer (model_output)
        final_answer = getattr(agent_result, output_field, None)
        if final_answer is None:
            final_answer = ""
        out_messages.append(ChatAssistantMessage(
            role="assistant",
            content=[text_content_block_from_string(str(final_answer))],
            tool_calls=None,
        ))

        return query, runtime, env, out_messages, extra_args
