"""Release inventory guards use synthetic archives, never extract their contents."""

import io
import stat
import tarfile
import zipfile

import pytest

from scripts import check_distribution_contents as inventory
from scripts.check_distribution_contents import check_archive

PREFIX = "dspy_security_bench-0.19.0"
TRACKED = {
    "dspy_security_bench/__init__.py",
    "dspy_security_bench/schemas/example.json",
    "pyproject.toml", "README.md", "LICENSE", "NOTICE",
}


def sdist(tmp_path, *, omit=None, extra=None, kind=tarfile.REGTYPE):
    path = tmp_path / f"{PREFIX}.tar.gz"
    names = sorted(TRACKED | {"PKG-INFO"})
    if omit:
        names.remove(omit)
    with tarfile.open(path, "w:gz") as archive:
        for name in names:
            member = tarfile.TarInfo(f"{PREFIX}/{name}")
            archive.addfile(member, io.BytesIO())
        if extra:
            member = tarfile.TarInfo(extra)
            member.type = kind
            member.linkname = "outside"
            archive.addfile(member, io.BytesIO())
    return path


def wheel(tmp_path, *, omit=None, extra=None, mode=None):
    path = tmp_path / f"{PREFIX}-py3-none-any.whl"
    names = sorted(name for name in TRACKED if name.startswith("dspy_security_bench/"))
    names += [f"{PREFIX}.dist-info/{name}" for name in (
        "METADATA", "WHEEL", "RECORD", "entry_points.txt", "licenses/LICENSE", "licenses/NOTICE"
    )]
    if omit:
        names.remove(omit)
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, "")
        if extra:
            member = zipfile.ZipInfo(extra)
            if mode is not None:
                member.external_attr = mode << 16
            archive.writestr(member, "")
    return path


def test_valid_archives_include_all_tracked_package_resources(tmp_path):
    assert check_archive(sdist(tmp_path), TRACKED, "0.19.0") == 7
    assert check_archive(wheel(tmp_path), TRACKED, "0.19.0") == 8


@pytest.mark.parametrize("relative", [
    "private-notes.txt", "assets/social/draft.md", "../escape", "/absolute",
    "dir//name", "dir/./name", "dir\\name", "C:private",
])
def test_sdist_rejects_untracked_and_unsafe_paths(tmp_path, relative):
    with pytest.raises(ValueError):
        check_archive(sdist(tmp_path, extra=f"{PREFIX}/{relative}"), TRACKED, "0.19.0")


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE])
def test_sdist_rejects_nonregular_members(tmp_path, kind):
    with pytest.raises(ValueError, match="regular"):
        check_archive(sdist(tmp_path, extra=f"{PREFIX}/link", kind=kind), TRACKED, "0.19.0")


def test_sdist_rejects_duplicates(tmp_path):
    with pytest.raises(ValueError, match="duplicate"):
        check_archive(sdist(tmp_path, extra=f"{PREFIX}/README.md"), TRACKED, "0.19.0")


@pytest.mark.parametrize("builder", [sdist, wheel])
def test_archives_reject_missing_resource(tmp_path, builder):
    path = builder(tmp_path, omit="dspy_security_bench/schemas/example.json")
    with pytest.raises(ValueError, match="missing"):
        check_archive(path, TRACKED, "0.19.0")


@pytest.mark.parametrize("extra", [
    "dspy_security_bench/private.json", "private.json", "../escape",
    f"{PREFIX}.dist-info/private.txt", "different.dist-info/METADATA",
])
def test_wheel_rejects_untracked_members_and_metadata(tmp_path, extra):
    with pytest.raises(ValueError):
        check_archive(wheel(tmp_path, extra=extra), TRACKED, "0.19.0")


def test_wheel_rejects_links(tmp_path):
    with pytest.raises(ValueError, match="regular"):
        check_archive(wheel(tmp_path, extra="link", mode=stat.S_IFLNK | 0o777), TRACKED, "0.19.0")


def test_version_mismatch_is_not_accepted(tmp_path):
    with pytest.raises(ValueError, match="version"):
        check_archive(sdist(tmp_path), TRACKED, "0.20.0")


def test_promotional_material_rejected_even_if_later_tracked(tmp_path):
    path = sdist(tmp_path, extra=f"{PREFIX}/assets/social/draft.md")
    with pytest.raises(ValueError, match="promotional"):
        check_archive(path, TRACKED | {"assets/social/draft.md"}, "0.19.0")


@pytest.mark.parametrize("marker,expected", [(b"*", 0), (b"*\n", 0), (b"secret", 1)])
def test_cli_handles_uv_marker_without_ignoring_arbitrary_files(tmp_path, monkeypatch, marker, expected):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    monkeypatch.setattr(inventory, "__file__", str(scripts / "check_distribution_contents.py"))
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.19.0"\n')
    monkeypatch.setattr(inventory.subprocess, "check_output", lambda *a, **k: "\0".join(TRACKED).encode())
    dist = tmp_path / "dist"
    dist.mkdir()
    sdist(dist)
    wheel(dist)
    (dist / ".gitignore").write_bytes(marker)
    assert inventory.main([str(dist)]) == expected
