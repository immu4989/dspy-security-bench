"""Preview and guarded application of a bounded local scaffold, not a sandbox."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from dspy_security_bench.jsonio import read_regular_bytes
from dspy_security_bench.outputio import check_directory, write_new_file

MAX_EXISTING_BYTES = 1_000_000


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ScaffoldFile:
    relative: Path
    action: str
    content: bytes = field(repr=False)
    existing_sha256: str | None = None
    existing_size: int | None = None

    def to_dict(self) -> dict:
        return {"path": self.relative.as_posix(), "action": self.action,
                "proposed_sha256": _sha(self.content), "proposed_size_bytes": len(self.content),
                "existing_sha256": self.existing_sha256, "existing_size_bytes": self.existing_size}


@dataclass(frozen=True)
class IntegrationPlan:
    root: Path
    agent_import: str
    files: tuple[ScaffoldFile, ...]

    @property
    def has_conflicts(self) -> bool:
        return any(item.action == "conflict" for item in self.files)

    def to_dict(self) -> dict:
        return {"schema_version": 1, "mode": "scaffold_preview", "agent": self.agent_import,
                "has_conflicts": self.has_conflicts, "files": [item.to_dict() for item in self.files],
                "boundary": "Read-only proposal, not a saved-plan execution token, runtime check, or transaction."}


@dataclass(frozen=True)
class IntegrationScaffoldResult:
    created: tuple[Path, ...]
    skipped: tuple[Path, ...]
    agent_import: str
    replaced: tuple[Path, ...] = ()
    conflicts: tuple[Path, ...] = ()


class ScaffoldWriteError(ValueError):
    def __init__(self, completed: tuple[Path, ...], attempted: Path):
        self.completed = completed
        self.attempted = attempted
        super().__init__("scaffold write failed; files/directories may remain, no rollback performed; review before retrying")


def _inspect(root: Path, relative: Path) -> bytes | None:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("invalid scaffold-relative destination")
    # Resolve the owner-selected root before planning. Beneath it, never accept
    # an observed link, reparse point, nondirectory ancestor, or special file.
    parents = list(root.parents)[::-1] + [root]
    parents.extend(root / parent for parent in list(relative.parents)[::-1] if parent != Path("."))
    for parent in parents:
        try:
            check_directory(parent)
        except FileNotFoundError:
            continue
    path = root / relative
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    raw = read_regular_bytes(path, MAX_EXISTING_BYTES)
    if len(raw) > MAX_EXISTING_BYTES:
        raise ValueError("existing scaffold file exceeds the comparison budget")
    return raw


def make_plan(root: Path, agent_import: str, targets: list[tuple[Path, str]], *, force: bool) -> IntegrationPlan:
    root = root.resolve()
    names = [path.as_posix().casefold() for path, _ in targets]
    if len(set(names)) != len(names):
        raise ValueError("generated scaffold destinations collide")
    for path, _ in targets:
        if any(parent.with_suffix(".py").as_posix().casefold() in names
               for parent in path.parents if parent != Path(".")):
            raise ValueError("generated Python module and package destinations collide")
    files = []
    for relative, text in targets:
        raw = text.encode("utf-8")
        existing = _inspect(root, relative)
        if existing is None:
            action = "create"
        elif existing == raw:
            action = "unchanged"
        else:
            action = "replace" if force else "conflict"
        files.append(ScaffoldFile(relative, action, raw, _sha(existing) if existing is not None else None,
                                  len(existing) if existing is not None else None))
    return IntegrationPlan(root, agent_import, tuple(files))


def _check_snapshot(plan: IntegrationPlan, item: ScaffoldFile) -> None:
    current = _inspect(plan.root, item.relative)
    current_hash = _sha(current) if current is not None else None
    if current_hash != item.existing_sha256 or (len(current) if current is not None else None) != item.existing_size:
        raise ValueError("scaffold destination changed after planning; inspect a fresh preview")


def _replace_file(path: Path, raw: bytes) -> None:
    # Stage a complete file on the same filesystem before replacing the entry.
    # This avoids truncation/hard-link mutation but is not a compare-and-swap or
    # a cross-file atomic transaction. Stable owner-controlled paths are required.
    descriptor, staging = tempfile.mkstemp(prefix=".dsb-scaffold-", suffix=".tmp", dir=path.parent)
    temporary = Path(staging)
    stream = None
    try:
        stream = os.fdopen(descriptor, "wb")
        with stream:
            if stream.write(raw) != len(raw):
                raise OSError("incomplete scaffold staging write")
        os.replace(temporary, path)
    finally:
        if stream is None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def apply_plan(plan: IntegrationPlan) -> IntegrationScaffoldResult:
    """Apply an in-memory trusted plan, rechecking observed bytes before writing.

    The CLI never loads serialized plans. A conflict stops every write. Later I/O
    failure may leave outputs; only staging files owned by this call are removed.
    """
    skipped = tuple(plan.root / item.relative for item in plan.files if item.action in {"conflict", "unchanged"})
    conflicts = tuple(plan.root / item.relative for item in plan.files if item.action == "conflict")
    if conflicts:
        return IntegrationScaffoldResult((), skipped, plan.agent_import, conflicts=conflicts)
    for item in plan.files:
        _check_snapshot(plan, item)
    created, replaced, completed = [], [], []
    for item in plan.files:
        if item.action == "unchanged":
            continue
        path = plan.root / item.relative
        try:
            _check_snapshot(plan, item)
            path.parent.mkdir(parents=True, exist_ok=True)
            _check_snapshot(plan, item)
            if item.action == "create":
                write_new_file(path, item.content)
                created.append(path)
            elif item.action == "replace":
                _replace_file(path, item.content)
                replaced.append(path)
            else:
                raise ValueError("invalid scaffold action")
            completed.append(item.relative)
        except (OSError, ValueError):
            raise ScaffoldWriteError(tuple(completed), item.relative) from None
    return IntegrationScaffoldResult(tuple(created), skipped, plan.agent_import, tuple(replaced))
