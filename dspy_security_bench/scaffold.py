"""Project scaffolding for the five-minute CI quickstart."""
from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

_PROVIDER_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "azure": "AZURE_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "google": "GEMINI_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "ollama": None,
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "together_ai": "TOGETHERAI_API_KEY",
    "vllm": None,
}


@dataclass(frozen=True)
class ScaffoldResult:
    created: tuple[Path, ...]
    skipped: tuple[Path, ...]


def _template(name: str) -> str:
    return files("dspy_security_bench.templates").joinpath(name).read_text()


def _provider_env(model: str) -> str:
    provider = model.split("/", 1)[0].lower()
    key = _PROVIDER_KEYS.get(provider)
    if key:
        return f"          {key}: ${{{{ secrets.{key} }}}}"
    if provider in _PROVIDER_KEYS:  # local provider; no credential expected
        return "          # This local provider does not require an API-key secret."
    return f"          # Add the API-key secret required by the {provider!r} provider."


def initialize_project(
    root: str | Path = ".",
    *,
    model: str = "openai/gpt-4o-mini",
    agent_import: str | None = None,
    include_workflow: bool = True,
    force: bool = False,
) -> ScaffoldResult:
    """Create a scan config and optional GitHub Action without overwriting by default."""
    root = Path(root)
    config_path = root / ".dspy-security-bench.yaml"
    targets = [(config_path, "config.yaml")]
    if include_workflow:
        targets.append((root / ".github/workflows/injection-scan.yml", "github-action.yml"))

    agent_block = f"  import: {agent_import}" if agent_import else f"  model: {model}"
    created: list[Path] = []
    skipped: list[Path] = []
    for path, template_name in targets:
        if path.exists() and not force:
            skipped.append(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        content = _template(template_name).replace("{{ agent }}", agent_block)
        content = content.replace("{{ provider env }}", _provider_env(model))
        project_install = "          pip install -e .\n" if agent_import else ""
        content = content.replace("{{ project install }}", project_install)
        path.write_text(content)
        created.append(path)
    return ScaffoldResult(tuple(created), tuple(skipped))
