"""Supply-chain invariants for the repository's own GitHub Actions."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
IMMUTABLE_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def test_every_external_action_is_pinned_to_a_full_commit_sha():
    references = []
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        for line_number, line in enumerate(workflow.read_text().splitlines(), start=1):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if not match or match.group(1).startswith("./"):
                continue
            references.append((workflow.name, line_number, match.group(1)))

    assert references
    unpinned = [
        f"{name}:{line_number} {reference}"
        for name, line_number, reference in references
        if not IMMUTABLE_ACTION.fullmatch(reference)
    ]
    assert not unpinned, "external actions must be SHA-pinned:\n" + "\n".join(unpinned)


def test_uv_bootstrap_version_is_explicit():
    workflow = (WORKFLOWS / "test.yml").read_text()
    assert 'version: "0.12.3"' in workflow


def test_ci_installs_from_lockfile_without_resolving_during_checks():
    workflow = (WORKFLOWS / "test.yml").read_text()
    assert "uv sync --locked --extra dev" in workflow
    assert "uv run --locked --no-sync pytest" in workflow
    assert "uv run --locked --no-sync ruff" in workflow
