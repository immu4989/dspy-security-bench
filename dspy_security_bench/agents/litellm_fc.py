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
import logging

from dspy_security_bench.agents.base import AgentResult, BenchTool, ToolCall

logger = logging.getLogger("dspy_security_bench.agents.litellm_fc")


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
        self.model = model
        self.max_iters = max_iters
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.num_retries = num_retries
        self.name = name or f"litellm-fc:{model}"

    def run(self, query: str, tools: list[BenchTool], *, system_directive: str = "") -> AgentResult:
        import litellm
        litellm.drop_params = True

        tools_by_name = {t.name: t for t in tools}
        tool_specs = [t.openai_schema() for t in tools]

        messages: list[dict] = []
        if system_directive:
            messages.append({"role": "system", "content": system_directive})
        messages.append({"role": "user", "content": query})

        trace: list[ToolCall] = []
        final_answer = ""

        for _ in range(self.max_iters):
            resp = litellm.completion(
                model=self.model,
                messages=messages,
                tools=tool_specs or None,
                tool_choice="auto" if tool_specs else None,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                num_retries=self.num_retries,
            )
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
                raw_args = tc.function.arguments or "{}"
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                except json.JSONDecodeError:
                    args = {}

                tool = tools_by_name.get(name)
                if tool is None:
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
            try:
                resp = litellm.completion(
                    model=self.model,
                    messages=messages + [{
                        "role": "user",
                        "content": "Provide your final answer now, using only what you already know.",
                    }],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    num_retries=self.num_retries,
                )
                final_answer = resp.choices[0].message.content or ""
            except Exception as e:  # pragma: no cover - defensive
                logger.warning("final-answer call failed: %s", e)
                final_answer = ""

        return AgentResult(final_answer=final_answer, tool_calls=trace)
