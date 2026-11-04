"""A framework-free function-calling agent built on litellm.

This is the reference `Agent` implementation and the main adoption unlock: it
lets anyone benchmark "model X with native function calling + defense Y" with
no DSPy involved, against any litellm-supported provider (OpenAI, Anthropic,
Mistral, DeepSeek, Groq, local vLLM/Ollama, ...).

It is deliberately minimal — a plain tool-use loop — so it is easy to read and
to trust as a baseline. Real deployments will have richer agents; this is the
"honest floor" of what a function-calling agent does.
"""
from __future__ import annotations

import json
import math

from dspy_security_bench.agents.base import (
    AgentResult,
    AgentResultError,
    BenchTool,
    ToolCall,
    require_text_answer,
)
from dspy_security_bench.agents.usage import _usage_field, normalize_usage
from dspy_security_bench.jsonio import decode_json_object


class LiteLLMFunctionCallingAgent:
    """Native function-calling agent over any litellm model.

    Args:
        model: litellm model string, e.g. "openai/gpt-4o-mini".
        max_iters: cap on tool-use rounds before forcing a final answer.
        temperature: sampling temperature.
        max_tokens: per-call output cap.
        num_retries: litellm auto-retry count for transient errors.
        name: display name (defaults to a slug of the model).
    """

    def __init__(
        self,
        model: str,
        max_iters: int = 8,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        num_retries: int = 5,
        name: str | None = None,
    ):
        if type(max_iters) is not int or not 1 <= max_iters <= 1000:
            raise ValueError("max_iters must be an integer from 1 to 1000")
        if type(max_tokens) is not int or max_tokens < 1:
            raise ValueError("max_tokens must be a positive integer")
        if type(num_retries) is not int or not 0 <= num_retries <= 100:
            raise ValueError("num_retries must be an integer from 0 to 100")
        self.model = model
        self.max_iters = max_iters
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.num_retries = num_retries
        self.name = name or f"litellm-fc:{model}"

    def run(self, query: str, tools: list[BenchTool], *, system_directive: str = "") -> AgentResult:
        names = [tool.name for tool in tools]
        if any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
            raise ValueError("tool names must be nonempty unique strings")
        import litellm

        tools_by_name = {t.name: t for t in tools}
        tool_specs = [t.openai_schema() for t in tools]

        messages: list[dict] = []
        if system_directive:
            messages.append({"role": "system", "content": system_directive})
        messages.append({"role": "user", "content": query})

        trace: list[ToolCall] = []
        final_answer = ""
        usage_reports: list[dict[str, int | float]] = []

        for _ in range(self.max_iters):
            resp = litellm.completion(
                model=self.model,
                messages=messages,
                tools=tool_specs or None,
                tool_choice="auto" if tool_specs else None,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                num_retries=self.num_retries,
                drop_params=True,
            )
            content, tool_calls = _completion_turn(resp, allow_tools=True)
            usage_reports.append(_response_usage(resp))

            if not tool_calls:
                final_answer = require_text_answer(content)
                break

            # Record the assistant turn (with its tool calls) so the model sees
            # its own calls on the next round.
            messages.append({
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls,
            })

            for tc in tool_calls:
                name = tc["function"]["name"]
                raw_args = tc["function"]["arguments"]
                invalid_arguments = False
                try:
                    args = _parse_tool_arguments(raw_args)
                except (TypeError, ValueError):
                    args = {}
                    invalid_arguments = True

                tool = tools_by_name.get(name)
                if invalid_arguments:
                    result = "[error] tool arguments must be a bounded, unambiguous JSON object; tool was not executed"
                elif tool is None:
                    result = f"[error] unknown tool {name!r}"
                else:
                    # THE load-bearing line: execute the real tool, mutating the
                    # live AgentDojo env so injection detection works.
                    result = tool(**args)

                if not isinstance(result, str):
                    raise AgentResultError("ToolCall.result must be text")
                trace.append(ToolCall(name=name, args=args, result=result))
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result,
                })
        else:
            # Ran out of iterations. Ask once for a final answer with no tools.
            # Provider failure is an execution error, not an empty measured answer.
            resp = litellm.completion(
                model=self.model,
                messages=messages + [{
                    "role": "user",
                    "content": "Provide your final answer now, using only what you already know.",
                }],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                num_retries=self.num_retries,
                drop_params=True,
            )
            final_answer, _ = _completion_turn(resp, allow_tools=False)
            usage_reports.append(_response_usage(resp))

        return AgentResult(final_answer=final_answer, tool_calls=trace,
                           usage=_complete_usage(usage_reports))


def _field(value, name):
    """Required response access: unlike optional telemetry, failures propagate."""
    return value.get(name) if isinstance(value, dict) else getattr(value, name, None)


# LiteLLM can normalize provider error/unknown reasons to "stop". Only these
# explicit normal termination reasons are supported when the original survives.
# Do not import the SDK's private map: it includes errors and defaults to stop.
_NATIVE_STOPS = frozenset({"stop", "stop_sequence", "end_turn", "COMPLETE", "eos_token", "eos", "STOP"})


def _completion_turn(response, *, allow_tools: bool) -> tuple[str | None, list[dict]]:
    """Admit one non-streaming assistant turn before performing any tool action.

    SDK defaults cannot be distinguished from provider evidence after conversion.
    Unknown native reasons require explicit adapter work, not optimistic scoring.
    This checks returned state, not whether the model fulfilled the user's task.
    """
    choices = _field(response, "choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise AgentResultError("LiteLLM response must contain exactly one choice")
    kind = _field(response, "object")
    if kind is not None and (not isinstance(kind, str) or kind != "chat.completion"):
        raise AgentResultError("LiteLLM response must be a non-streaming chat completion")
    choice = choices[0]
    finish = _field(choice, "finish_reason")
    if not isinstance(finish, str) or finish not in {"stop", "tool_calls"}:
        raise AgentResultError("LiteLLM response has no supported completed turn")
    provider_fields = _field(choice, "provider_specific_fields")
    if provider_fields is not None and not isinstance(provider_fields, dict):
        raise AgentResultError("LiteLLM native completion state must be a dictionary")
    native = _field(provider_fields, "native_finish_reason")
    native_stops = _NATIVE_STOPS | {"tool_calls", "tool_use"} if finish == "tool_calls" else _NATIVE_STOPS
    if native is not None and (not isinstance(native, str) or native not in native_stops):
        raise AgentResultError("LiteLLM native finish reason is not a supported completed turn")
    message = _field(choice, "message")
    role = _field(message, "role")
    if not isinstance(role, str) or role != "assistant":
        raise AgentResultError("LiteLLM response must be attributed to the assistant")
    if _field(message, "function_call") is not None:
        raise AgentResultError("LiteLLM legacy function-call state is unsupported")
    calls = _field(message, "tool_calls")
    if calls is None:
        calls = []
    elif not isinstance(calls, list):
        raise AgentResultError("LiteLLM tool_calls must be a list or absent")
    content = _field(message, "content")
    if not calls:
        if finish != "stop":
            raise AgentResultError("LiteLLM tool-call completion is missing its calls")
        return require_text_answer(content), []
    if not allow_tools or finish != "tool_calls":
        raise AgentResultError("LiteLLM pending tool calls are not a final answer")
    if content is not None and not isinstance(content, str):
        raise AgentResultError("LiteLLM assistant tool-turn content must be text or null")
    admitted = []
    identifiers = set()
    for call in calls:
        identifier, kind = _field(call, "id"), _field(call, "type")
        function = _field(call, "function")
        name, arguments = _field(function, "name"), _field(function, "arguments")
        if not isinstance(identifier, str) or not identifier.strip() or identifier in identifiers:
            raise AgentResultError("LiteLLM tool-call IDs must be nonblank and unique within a turn")
        if not isinstance(kind, str) or kind != "function" or not isinstance(name, str) or not name.strip():
            raise AgentResultError("LiteLLM tool calls must name a function")
        identifiers.add(identifier)
        # Retain SDK extensions such as provider-specific signatures, but execute
        # only the fields just admitted. Validate the entire batch before effects.
        dump = getattr(call, "model_dump", None)
        payload = call if isinstance(call, dict) else dump() if callable(dump) else {}
        if not isinstance(payload, dict):
            raise AgentResultError("LiteLLM serialized tool call must be a dictionary")
        function_payload = payload.get("function")
        function_payload = function_payload if isinstance(function_payload, dict) else {}
        admitted.append({**payload, "id": identifier, "type": "function",
                         "function": {**function_payload, "name": name, "arguments": arguments}})
    return content, admitted


def _parse_tool_arguments(value) -> dict:
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("tool argument keys must be strings")
        value = json.dumps(value, allow_nan=False)
    if not isinstance(value, str) or len(value) > 1_000_000:
        raise ValueError("tool arguments must be bounded JSON text or an object")
    return decode_json_object(value.encode("utf-8"), 1_000_000)


def _response_usage(response) -> dict[str, int | float]:
    """Optional SDK telemetry must not prevent processing a returned response."""
    raw = _usage_field(response, "usage")
    values = {key: _usage_field(raw, key) for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
    hidden = _usage_field(response, "_hidden_params")
    values["estimated_cost_usd"] = _usage_field(hidden, "response_cost") if isinstance(hidden, dict) else None
    return normalize_usage(values)


def _complete_usage(reports: list[dict[str, int | float]]) -> dict[str, int | float]:
    """Only sum fields reported validly on every returned completion response.

    A missing field anywhere makes that run-level total unknown. SDK retries,
    tool costs, and provider-side work absent from responses are not measured.
    """
    if not reports:
        return {}
    fields = set(reports[0]).intersection(*(set(report) for report in reports[1:]))
    totals = {}
    for key in sorted(fields):
        total = sum(report[key] for report in reports)
        if isinstance(total, float) and not math.isfinite(total):
            continue
        totals[key] = total
    return totals
