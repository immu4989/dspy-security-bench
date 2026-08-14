"""Cross-file checks for public metadata and documentation consistency."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def _project_version() -> str:
    metadata = (ROOT / "pyproject.toml").read_text()
    project = metadata.split("[project]", 1)[1].split("\n[", 1)[0]
    match = re.search(r'^version = "([^"]+)"$', project, re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_public_release_metadata_uses_one_version():
    version = _project_version()
    citation = yaml.safe_load((ROOT / "CITATION.cff").read_text())

    assert str(citation["version"]) == version
    assert f"## [{version}]" in (ROOT / "CHANGELOG.md").read_text()
    assert f"@v{version}" in (ROOT / "README.md").read_text()
    proofrun = (ROOT / ".github/workflows/proofrun.yml").read_text()
    assert set(re.findall(r"ref: v(\d+\.\d+\.\d+)", proofrun)) == {version}


def test_relative_markdown_links_resolve_inside_the_repository():
    missing = []
    for document in ROOT.rglob("*.md"):
        if any(part in {".git", ".venv"} for part in document.parts):
            continue
        for line_number, line in enumerate(document.read_text().splitlines(), start=1):
            for match in MARKDOWN_LINK.finditer(line):
                raw_target = match.group(1).strip().strip("<>")
                target = raw_target.split("#", 1)[0]
                if not target or target.startswith(("http://", "https://", "mailto:")):
                    continue
                resolved = (document.parent / target).resolve()
                try:
                    resolved.relative_to(ROOT)
                except ValueError:
                    missing.append(f"{document.relative_to(ROOT)}:{line_number} outside repo: {target}")
                    continue
                if not resolved.exists():
                    missing.append(f"{document.relative_to(ROOT)}:{line_number} missing: {target}")

    assert not missing, "broken relative Markdown links:\n" + "\n".join(missing)
