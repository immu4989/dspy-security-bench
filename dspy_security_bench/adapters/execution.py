"""Prevent upstream benchmark exception fallbacks from becoming measurements."""

from __future__ import annotations

MEASUREMENT_PROTOCOL = "complete-binary-observations-v2"


class BenchmarkExecutionError(RuntimeError):
    """A task did not yield a valid measurement; no attack outcome is inferred."""


class ExecutionCheckedSuite:
    """Local suite proxy, not a global patch of AgentDojo or provider SDKs.

    AgentDojo catches selected provider exceptions around run_task_with_pipeline
    and converts them into binary outcomes. Wrap exceptions before that fallback
    can classify them. Errors suppressed *inside* a user agent or evaluator are
    not observable here. Deliberate AbortAgentError handling within AgentDojo
    retains its existing environment-based scoring semantics.
    """

    def __init__(self, suite):
        self._suite = suite

    def __getattr__(self, name):
        return getattr(self._suite, name)

    def run_task_with_pipeline(self, *args, **kwargs):
        try:
            result = self._suite.run_task_with_pipeline(*args, **kwargs)
        except Exception:
            # Provider messages can contain prompts, account IDs, or credentials.
            # Preserve no exception text in the wrapper or public CLI diagnostic.
            raise BenchmarkExecutionError(
                "task execution or evaluation failed; no binary outcome was recorded"
            ) from None
        if not isinstance(result, tuple) or len(result) != 2 or any(type(value) is not bool for value in result):
            raise BenchmarkExecutionError("task must return two measured boolean outcomes")
        return result


def require_fresh_execution(force_rerun: bool) -> None:
    if force_rerun is not True:
        raise ValueError(
            "cached AgentDojo outcomes lack verified execution-error accounting; "
            "use force_rerun=True or replay retained scan evidence without model calls"
        )
