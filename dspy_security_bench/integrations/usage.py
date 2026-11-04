"""Optional native telemetry admission and callback-scoped token collection.

Importing this module does not import any optional framework SDK.
"""

from __future__ import annotations

from threading import Lock
from typing import Any
from uuid import UUID

from dspy_security_bench.agents import normalize_usage

_UNREADABLE_USAGE = object()
_TOKEN_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")


def _usage_field(value: Any, name: str) -> Any:
    try:
        return value.get(name) if isinstance(value, dict) else getattr(value, name, None)
    except Exception:
        # Optional telemetry is not a task-validity gate. Do not expose raw
        # metadata exceptions; BaseException control flow still propagates.
        return _UNREADABLE_USAGE


def _usage(values: Any, *path: str) -> dict[str, int | float]:
    """Admit SDK-exposed fields without inventing totals or choosing conflicts.

    Missing, malformed, conflicting, and unreadable quantities remain unknown.
    SDK defaults/computed properties are not raw provider receipts or billing
    evidence. Only the optional metadata path is guarded, not native execution.
    """
    for name in path:
        values = _usage_field(values, name)
        if values is None or values is _UNREADABLE_USAGE:
            return {}
    if callable(values):
        try:
            values = values()
        except Exception:
            return {}
    aliases = {
        "prompt_tokens": ("prompt_tokens", "input_tokens", "request_tokens"),
        "completion_tokens": ("completion_tokens", "output_tokens", "response_tokens"),
        "total_tokens": ("total_tokens",),
        "requests": ("requests",),
        "estimated_cost_usd": ("estimated_cost_usd",),
    }
    result: dict[str, int | float] = {}
    for target, sources in aliases.items():
        candidates = []
        for source in sources:
            value = _usage_field(values, source)
            if value is None:
                continue
            if target == "requests":
                normalized = (
                    value if isinstance(value, int) and not isinstance(value, bool) and value >= 0
                    else _UNREADABLE_USAGE
                )
            else:
                normalized = normalize_usage({target: value}).get(target, _UNREADABLE_USAGE)
            if normalized is _UNREADABLE_USAGE:
                break
            candidates.append(normalized)
        else:
            if candidates and all(value == candidates[0] for value in candidates):
                result[target] = candidates[0]
    return result


def _langchain_receipt(response: Any) -> dict[str, int | float]:
    """Only a single completed chat generation has unambiguous receipt scope."""
    try:
        generations = response.generations
        if not isinstance(generations, list) or len(generations) != 1:
            return {}
        batch = generations[0]
        if not isinstance(batch, list) or len(batch) != 1:
            return {}
        message = batch[0].message
        if message.type != "ai":
            return {}
        admitted = _usage(message, "usage_metadata")
        return {key: admitted[key] for key in _TOKEN_FIELDS if key in admitted}
    except Exception:
        return {}


class _LangChainUsageLedger:
    """Numeric-only, per-invocation accounting for observed model callbacks.

    This does not measure hidden provider work, authenticate events, or bound
    trusted in-process callbacks. Unknown/duplicate lifecycle events fail closed
    for telemetry only. No prompts, outputs, model names, or exceptions are saved.
    """

    run_inline = True

    def __init__(self):
        super().__init__()
        self._lock = Lock()
        self._records: dict[UUID | str, dict[str, int | float] | None] = {}
        self._invalid = False
        self._snapshot: dict[str, int | float] | None = None

    def _record(self, run_id, receipt, *, starting=False):
        with self._lock:
            if self._snapshot is not None:
                return
            if not isinstance(run_id, (UUID, str)) or not run_id:
                self._invalid = True
            elif starting:
                if run_id in self._records:
                    self._invalid = True
                else:
                    self._records[run_id] = None
            elif run_id not in self._records or self._records[run_id] is not None:
                self._invalid = True
            else:
                self._records[run_id] = receipt

    def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
        self._record(run_id, None, starting=True)

    def on_llm_start(self, serialized, prompts, *, run_id, **kwargs):
        self._record(run_id, None, starting=True)

    def on_llm_end(self, response, *, run_id, **kwargs):
        self._record(run_id, _langchain_receipt(response))

    def on_llm_error(self, error, *, run_id, **kwargs):
        self._record(run_id, {})

    def usage(self) -> dict[str, int | float]:
        with self._lock:
            if self._snapshot is None:
                self._snapshot = {}
                receipts = list(self._records.values())
                if not self._invalid and receipts and all(receipt is not None for receipt in receipts):
                    for key in _TOKEN_FIELDS:
                        if all(key in receipt for receipt in receipts):
                            self._snapshot[key] = sum(receipt[key] for receipt in receipts)
            return dict(self._snapshot)


def _langchain_usage_callback():
    from langchain_core.callbacks import BaseCallbackHandler

    class Callback(_LangChainUsageLedger, BaseCallbackHandler):
        pass

    return Callback()
