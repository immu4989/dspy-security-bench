"""Optional-dependency bridges for popular Python agent frameworks.

Each bridge implements the package's small framework-neutral ``Agent``
protocol. Framework imports stay lazy so the base benchmark remains lightweight.
"""

from dspy_security_bench.integrations.catalog import (
    FRAMEWORKS,
    FrameworkSpec,
    detect_frameworks,
    get_framework,
)
from dspy_security_bench.integrations.frameworks import (
    AutoGenAdapter,
    CallbackAdapter,
    CrewAIAdapter,
    LangChainAdapter,
    OpenAIAgentsAdapter,
    PydanticAIAdapter,
)
from dspy_security_bench.integrations.tools import NativeToolExecutionError

__all__ = [
    "AutoGenAdapter",
    "CallbackAdapter",
    "CrewAIAdapter",
    "FRAMEWORKS",
    "FrameworkSpec",
    "LangChainAdapter",
    "NativeToolExecutionError",
    "OpenAIAgentsAdapter",
    "PydanticAIAdapter",
    "detect_frameworks",
    "get_framework",
]
