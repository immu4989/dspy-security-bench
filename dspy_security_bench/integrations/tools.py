"""Native adapter specialization of the shared supplied-tool lifecycle."""

from dspy_security_bench.agents.base import AgentToolExecutionError
from dspy_security_bench.agents.tools import _ToolSession as _SharedToolSession


class NativeToolExecutionError(AgentToolExecutionError):
    """Supplied native tool execution did not produce a complete measurement."""


class _ToolSession(_SharedToolSession):
    # Preserve the native bridge's public error type and fixed diagnostics.
    _error_type = NativeToolExecutionError
    _scope = "native"
