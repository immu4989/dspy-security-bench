"""Framework catalog and dependency-manifest detection for BYOA onboarding."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FrameworkSpec:
    key: str
    label: str
    adapter: str
    import_name: str | None
    package_hint: str
    default_model: str | None
    required_env: tuple[str, ...]
    markers: tuple[str, ...]
    docs_url: str


FRAMEWORKS: tuple[FrameworkSpec, ...] = (
    FrameworkSpec(
        key="openai-agents",
        label="OpenAI Agents SDK",
        adapter="OpenAIAgentsAdapter",
        import_name="agents",
        package_hint="openai-agents>=0.20",
        default_model="gpt-5.6",
        required_env=("OPENAI_API_KEY",),
        markers=("openai-agents",),
        docs_url="https://developers.openai.com/api/docs/guides/agents/quickstart",
    ),
    FrameworkSpec(
        key="langchain",
        label="LangChain / LangGraph",
        adapter="LangChainAdapter",
        import_name="langchain",
        package_hint='"langchain[openai]>=1.3"',
        default_model="openai:gpt-5.6",
        required_env=("OPENAI_API_KEY",),
        markers=("langchain", "langgraph"),
        docs_url="https://docs.langchain.com/oss/python/langchain/agents",
    ),
    FrameworkSpec(
        key="pydantic-ai",
        label="Pydantic AI",
        adapter="PydanticAIAdapter",
        import_name="pydantic_ai",
        package_hint="pydantic-ai>=2.29",
        default_model="openai:gpt-5.6",
        required_env=("OPENAI_API_KEY",),
        markers=("pydantic-ai", "pydantic_ai"),
        docs_url="https://pydantic.dev/docs/ai/tools-toolsets/tools/",
    ),
    FrameworkSpec(
        key="crewai",
        label="CrewAI",
        adapter="CrewAIAdapter",
        import_name="crewai",
        package_hint="\"crewai>=1.15; python_version < '3.14'\"",
        default_model="openai/gpt-5.6",
        required_env=("OPENAI_API_KEY",),
        markers=("crewai",),
        docs_url="https://docs.crewai.com/en/concepts/agents",
    ),
    FrameworkSpec(
        key="autogen",
        label="Microsoft AutoGen AgentChat",
        adapter="AutoGenAdapter",
        import_name="autogen_agentchat",
        package_hint='"autogen-agentchat>=0.7" "autogen-ext[openai]>=0.7"',
        default_model="gpt-5.6",
        required_env=("OPENAI_API_KEY",),
        markers=("autogen-agentchat", "autogen_agentchat", "pyautogen"),
        docs_url="https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/agents.html",
    ),
    FrameworkSpec(
        key="mcp",
        label="MCP or custom agent loop",
        adapter="CallbackAdapter",
        import_name=None,
        package_hint="your existing MCP/client package",
        default_model=None,
        required_env=(),
        markers=("fastmcp", "mcp"),
        docs_url="https://modelcontextprotocol.io/",
    ),
)

_BY_KEY = {spec.key: spec for spec in FRAMEWORKS}
_ALIASES = {
    "openai": "openai-agents",
    "openai-agents-sdk": "openai-agents",
    "langgraph": "langchain",
    "pydantic": "pydantic-ai",
    "crew": "crewai",
    "microsoft-autogen": "autogen",
    "custom": "mcp",
}


def get_framework(name: str) -> FrameworkSpec:
    key = _ALIASES.get(name.strip().lower(), name.strip().lower())
    try:
        return _BY_KEY[key]
    except KeyError as exc:
        supported = ", ".join(spec.key for spec in FRAMEWORKS)
        raise ValueError(f"unknown framework {name!r}; choose one of: {supported}") from exc


def detect_frameworks(root: str | Path = ".") -> list[tuple[FrameworkSpec, tuple[str, ...]]]:
    """Detect direct framework declarations without importing user code.

    Inspect bounded static declarations, including optional/development groups.
    This is not dependency resolution or proof that a framework is installed or
    used. Lockfiles, comments, and unrelated metadata do not select an adapter.
    """

    # Offline evidence replay imports the catalog via tracing but does not need
    # onboarding parsers. Preserve its stdlib + YAML-only dependency boundary.
    from packaging.utils import canonicalize_name

    from dspy_security_bench.integrations.dependencies import declared_dependencies

    declarations = declared_dependencies(Path(root))
    evidence: dict[str, set[str]] = {spec.key: set() for spec in FRAMEWORKS}
    for spec in FRAMEWORKS:
        for marker in spec.markers:
            evidence[spec.key].update(declarations.get(canonicalize_name(marker), ()))
    return [(spec, tuple(sorted(evidence[spec.key]))) for spec in FRAMEWORKS if evidence[spec.key]]
