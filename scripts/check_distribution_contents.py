"""Audit local release archives against Git-tracked source paths, without extraction.

The CLI checks inventory and source-file byte identity, not authenticity, secret
absence, build reproducibility, or the semantics of generated package metadata.
Run from a reviewed checkout after building, before uploading any distributions.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

MAX_MEMBERS = 20_000
MAX_ARCHIVE_BYTES = 100_000_000
MAX_EXPANDED_BYTES = 500_000_000
PACKAGE = "dspy_security_bench/"
GENERATED_WHEEL = {"METADATA", "WHEEL", "RECORD", "entry_points.txt"}


def _safe_name(name: str) -> bool:
    return bool(name) and not any(c in name for c in "\\\x00:") and all(
        part not in {"", ".", ".."} for part in name.split("/")
    )


def _digest(stream) -> str:
    digest = hashlib.sha256()
    consumed = 0
    while chunk := stream.read(1024 * 1024):
        consumed += len(chunk)
        if consumed > MAX_EXPANDED_BYTES:
            raise ValueError("source file exceeds the supported content budget")
        digest.update(chunk)
    return digest.hexdigest()


def source_digests(root: Path, tracked: set[str]) -> dict[str, str]:
    """Snapshot reviewed checkout bytes; never follow source-file symlinks."""
    result = {}
    for name in sorted(tracked):
        path = root / name
        if not _safe_name(name) or path.is_symlink() or not path.is_file():
            raise ValueError("tracked source must contain safe regular files")
        if any((root / parent).is_symlink() for parent in Path(name).parents if parent != Path(".")):
            raise ValueError("tracked source must not traverse symbolic links")
        with path.open("rb") as stream:
            result[name] = _digest(stream)
    return result


def check_archive(path: Path, tracked: set[str], version: str, expected_digests: dict[str, str] | None = None) -> int:
    """Reject unexpected members, links, duplicates, and missing package resources."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("distribution must be a bounded regular file")
    prefix = f"dspy_security_bench-{version}"
    files: set[str] = set()
    seen: set[str] = set()
    expanded = 0

    def verify_content(name: str, stream) -> None:
        if expected_digests is not None:
            expected = expected_digests.get(name)
            if expected is None or _digest(stream) != expected:
                raise ValueError("distribution source bytes differ from the reviewed checkout")

    def accept(name: str, size: int) -> None:
        nonlocal expanded
        if not _safe_name(name) or name in seen:
            raise ValueError("archive contains an unsafe or duplicate member path")
        seen.add(name)
        expanded += size
        if len(seen) > MAX_MEMBERS or size < 0 or expanded > MAX_EXPANDED_BYTES:
            raise ValueError("archive exceeds the supported inventory budget")

    if path.name == f"{prefix}.tar.gz":
        with tarfile.open(path, "r|gz") as archive:
            for member in archive:
                accept(member.name, member.size)
                if not member.isfile():
                    raise ValueError("source archive must contain regular files only")
                root, separator, relative = member.name.partition("/")
                if not separator or root != prefix:
                    raise ValueError("source archive has an unexpected root")
                if relative != "PKG-INFO" and relative not in tracked:
                    raise ValueError("source archive contains a path not tracked by Git")
                if relative.startswith("assets/social/"):
                    raise ValueError("source archive contains local promotional material")
                if relative in tracked:
                    with archive.extractfile(member) as stream:
                        verify_content(relative, stream)
                files.add(relative)
        required = {"PKG-INFO", "pyproject.toml", "README.md", "LICENSE", "NOTICE"}
    elif path.name == f"{prefix}-py3-none-any.whl":
        info_prefix = f"{prefix}.dist-info/"
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                accept(member.filename, member.file_size)
                mode = member.external_attr >> 16
                if member.is_dir() or stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                    raise ValueError("wheel must contain regular files only")
                name = member.filename
                if name.startswith(PACKAGE) and name in tracked:
                    with archive.open(member) as stream:
                        verify_content(name, stream)
                    files.add(name)
                elif name.startswith(info_prefix):
                    relative = name[len(info_prefix):]
                    if relative not in GENERATED_WHEEL | {"licenses/LICENSE", "licenses/NOTICE"}:
                        raise ValueError("wheel contains unexpected generated metadata")
                    if relative.startswith("licenses/"):
                        with archive.open(member) as stream:
                            verify_content(relative.removeprefix("licenses/"), stream)
                    files.add(name)
                else:
                    raise ValueError("wheel contains an unexpected or untracked path")
        required = {info_prefix + name for name in GENERATED_WHEEL}
        required |= {info_prefix + "licenses/" + name for name in ("LICENSE", "NOTICE")}
    else:
        raise ValueError("unexpected distribution name or version")
    required |= {name for name in tracked if name.startswith(PACKAGE)}
    if not required <= files:
        raise ValueError("distribution is missing required package files or metadata")
    return len(files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        project = (root / "pyproject.toml").read_text(encoding="utf-8")
        version = re.search(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$', project, re.M)
        if version is None:
            raise ValueError("cannot resolve the reviewed package version")
        tracked = set(subprocess.check_output(
            ["git", "ls-files", "-z"], cwd=root
        ).decode("utf-8").rstrip("\x00").split("\x00"))
        expected_digests = source_digests(root, tracked)
        distributions = sorted(args.directory.iterdir())
        # uv creates this exact one-byte marker in its output directory. It is
        # not a distribution; allow no other sidecar or hidden file.
        marker = args.directory / ".gitignore"
        if marker in distributions:
            if marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 2:
                raise ValueError("invalid build-directory marker")
            if marker.read_bytes() not in {b"*", b"*\n"}:
                raise ValueError("invalid build-directory marker")
            distributions.remove(marker)
        if len(distributions) != 2:
            raise ValueError("expected exactly one wheel and one source archive")
        suffixes = {path.suffix for path in distributions}
        if suffixes != {".whl", ".gz"}:
            raise ValueError("expected exactly one wheel and one source archive")
        for path in distributions:
            count = check_archive(path, tracked, version.group(1), expected_digests)
            print(f"{path.name}: {count} approved inventory paths; tracked source bytes match checkout")
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, subprocess.CalledProcessError):
        # Do not echo unexpected archive filenames or private paths from failures.
        print("Distribution inventory check failed; review build inputs and archive membership.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
