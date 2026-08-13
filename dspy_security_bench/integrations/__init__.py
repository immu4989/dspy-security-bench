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

__all__ = [
    "AutoGenAdapter",
    "CallbackAdapter",
    "CrewAIAdapter",
    "FRAMEWORKS",
    "FrameworkSpec",
    "LangChainAdapter",
    "OpenAIAgentsAdapter",
    "PydanticAIAdapter",
    "detect_frameworks",
    "get_framework",
]
