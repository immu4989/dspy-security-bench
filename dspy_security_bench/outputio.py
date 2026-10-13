"""Exclusive local output helpers; callers must own stable parent directories."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def check_directory(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
        raise ValueError("unlinked directory required")


def check_new_directory(output: Path) -> Path:
    output = output.absolute()
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("destination already exists")
    for parent in output.parents:
        check_directory(parent)
    return output


def write_new_file(path: Path, raw: bytes) -> None:
    """Never overwrite a file or final link; errors can leave a partial new file."""
    # Restrictive POSIX creation modes supplement deployment-owned ACLs. EXCL
    # rejects existing final links, including dangling ones, without following.
    with open(path, "xb", opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        if stream.write(raw) != len(raw):
            raise OSError("incomplete write")
