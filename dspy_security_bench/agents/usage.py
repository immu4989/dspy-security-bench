"""Normalize optional benchmark telemetry without making it a task-validity gate."""

from __future__ import annotations

import math
from typing import Any

_UNREADABLE_USAGE = object()


def _usage_field(value: Any, name: str) -> Any:
    """Read optional data without exposing accessor failures or coercing values."""
    try:
        return value.get(name) if isinstance(value, dict) else getattr(value, name, None)
    except Exception:
        # Optional telemetry is not a task-validity gate. BaseException control
        # flow still propagates; no native model/tool execution is guarded here.
        return _UNREADABLE_USAGE


def normalize_usage(raw: object) -> dict[str, int | float]:
    """Retain supported valid fields; absence/invalidity means unknown, not zero.

    Counts must be nonnegative integers, and USD cost finite and nonnegative.
    Boolean/string values are not coerced. Other fields are omitted. This does
    not authenticate provider reports, reconcile billing, infer missing totals,
    or impose resource limits on trusted in-process objects.
    """
    if not isinstance(raw, dict):
        return {}
    normalized: dict[str, int | float] = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            normalized[key] = value
    cost = raw.get("estimated_cost_usd")
    if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
        try:
            finite_cost = float(cost)
        except (OverflowError, ValueError):
            finite_cost = None
        if finite_cost is not None and math.isfinite(finite_cost):
            normalized["estimated_cost_usd"] = finite_cost
    return normalized
