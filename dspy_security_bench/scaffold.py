"""Project scaffolding for the five-minute CI quickstart."""
from __future__ import annotations

import json
import re
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
    on_pull_request: bool = False,
) -> ScaffoldResult:
    """Create a scan config and optional GitHub Action without overwriting by default."""
    root = Path(root).resolve()
    selected = agent_import if agent_import is not None else model
    if not isinstance(selected, str) or not selected.strip() or len(selected) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in selected):
        raise ValueError("agent model/import must be bounded single-line text")
    if agent_import is not None and not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*", agent_import):
        raise ValueError("agent import must be a dotted module:callable")
    config_path = root / ".dspy-security-bench.yaml"
    targets = [(config_path, "config.yaml")]
    if include_workflow:
        targets.append((root / ".github/workflows/injection-scan.yml", "github-action.yml"))

    agent_block = f"  import: {json.dumps(agent_import)}" if agent_import else f"  model: {json.dumps(model)}"
    created: list[Path] = []
    skipped: list[Path] = []
    pending: list[tuple[Path, str]] = []
    for path, template_name in targets:
        cursor = path
        while cursor != root:
            if cursor.is_symlink():
                raise ValueError("refusing to scaffold through a symbolic link")
            if cursor != path and cursor.exists() and not cursor.is_dir():
                raise ValueError("scaffold parent must be a directory")
            cursor = cursor.parent
        if path.exists() and not path.is_file():
            raise ValueError("scaffold output must be a regular file")
        if path.exists() and not force:
            skipped.append(path)
            continue
        if path.exists() and path.stat().st_nlink > 1:
            raise ValueError("refusing to overwrite a multiply linked scaffold file")
        content = _template(template_name).replace("{{ agent }}", agent_block)
        provider_env = (_provider_env(model) if agent_import is None else
                        "          # Add only credentials explicitly required by your agent factory.")
        content = content.replace("{{ provider env }}", provider_env)
        if on_pull_request:
            content = content.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n")
        project_install = "          pip install -e .\n" if agent_import else ""
        content = content.replace("{{ project install }}", project_install)
        pending.append((path, content))

    for path, content in pending:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w" if force else "x", encoding="utf-8") as stream:
            stream.write(content)
        created.append(path)
    return ScaffoldResult(tuple(created), tuple(skipped))
