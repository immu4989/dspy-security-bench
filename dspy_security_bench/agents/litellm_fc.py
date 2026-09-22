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

from dspy_security_bench.agents.base import AgentResult, BenchTool, ToolCall
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
        usage: dict[str, int | float] = {}

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
            _merge_usage(usage, _response_usage(resp))
            msg = resp.choices[0].message
            tool_calls = getattr(msg, "tool_calls", None)

            if not tool_calls:
                final_answer = msg.content or ""
                break

            # Record the assistant turn (with its tool calls) so the model sees
            # its own calls on the next round.
            messages.append({
                "role": "assistant",
                "content": msg.content or None,
                "tool_calls": [tc.model_dump() if hasattr(tc, "model_dump") else tc for tc in tool_calls],
            })

            for tc in tool_calls:
                name = tc.function.name
                raw_args = tc.function.arguments
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

                trace.append(ToolCall(name=name, args=args, result=result))
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": str(result),
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
            _merge_usage(usage, _response_usage(resp))
            final_answer = resp.choices[0].message.content or ""

        return AgentResult(final_answer=final_answer, tool_calls=trace, usage=usage)


def _parse_tool_arguments(value) -> dict:
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("tool argument keys must be strings")
        value = json.dumps(value, allow_nan=False)
    if not isinstance(value, str) or len(value) > 1_000_000:
        raise ValueError("tool arguments must be bounded JSON text or an object")
    return decode_json_object(value.encode("utf-8"), 1_000_000)


def _response_usage(response) -> dict[str, int | float]:
    """Extract portable token/cost fields without depending on provider shape."""
    raw = getattr(response, "usage", None)
    values: dict[str, int | float] = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = getattr(raw, key, None)
        if value is None and isinstance(raw, dict):
            value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            values[key] = value
    hidden = getattr(response, "_hidden_params", None)
    cost = hidden.get("response_cost") if isinstance(hidden, dict) else None
    if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
        try:
            estimate = float(cost)
        except OverflowError:
            estimate = math.inf
        if math.isfinite(estimate):
            values["estimated_cost_usd"] = estimate
    return values


def _merge_usage(total: dict[str, int | float], addition: dict[str, int | float]) -> None:
    for key, value in addition.items():
        total[key] = total.get(key, 0) + value
