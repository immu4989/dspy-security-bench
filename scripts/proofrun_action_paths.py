"""Prepare new workspace-local action outputs without replacing retained evidence.

This is a preflight for trusted workflow inputs, not an OS sandbox against code
running concurrently with filesystem access. The CLI rechecks and writes files
exclusively after this helper creates only the required parent directories.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def prepare_outputs(environment, workspace: Path) -> tuple[Path, ...]:
    kind = environment.get("PROOFRUN_EVIDENCE_KIND")
    if kind not in ("impact", "control", "incident", "source", "authority"):
        raise ValueError("unsupported evidence kind")
    workspace = workspace.resolve(strict=True)
    names = [environment.get("PROOFRUN_OUTPUT", "")]
    if kind == "control":
        names.append(environment.get("PROOFRUN_CARD_OUTPUT", ""))
    paths = []
    for name in names:
        if (not isinstance(name, str) or not name.strip()
                or any(ord(c) < 32 or ord(c) == 127 or c in "*?[]\\" for c in name)):
            raise ValueError("outputs must be literal non-empty paths")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("outputs must be workspace-relative paths without parent traversal")
        path = workspace / relative
        if path == workspace or path.exists():
            raise ValueError("outputs must be new files")
        for parent in (path, *path.parents):
            if parent == workspace:
                break
            if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                raise ValueError("outputs cannot traverse symlinks or non-directories")
        paths.append(path)
    if len(set(paths)) != len(paths) or any(a in b.parents for a in paths for b in paths if a != b):
        raise ValueError("output paths must be distinct and cannot contain one another")
    # Validate the complete layout before creating any directory.
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
    return tuple(paths)


def main() -> int:
    try:
        prepare_outputs(os.environ, Path.cwd())
    except (OSError, ValueError):
        print("[proofrun action] invalid output layout: use distinct new workspace-relative files; "
              "symlinks, traversal, and glob patterns are not allowed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
