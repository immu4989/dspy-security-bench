"""Release inventory guards use synthetic archives, never extract their contents."""

import base64
import csv
import hashlib
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


def sdist(tmp_path, *, omit=None, extra=None, kind=tarfile.REGTYPE, contents=None):
    path = tmp_path / f"{PREFIX}.tar.gz"
    names = sorted(TRACKED | {"PKG-INFO"})
    if omit:
        names.remove(omit)
    with tarfile.open(path, "w:gz") as archive:
        for name in names:
            member = tarfile.TarInfo(f"{PREFIX}/{name}")
            data = (contents or {}).get(name, b"")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if extra:
            member = tarfile.TarInfo(extra)
            member.type = kind
            member.linkname = "outside"
            archive.addfile(member, io.BytesIO())
    return path


def wheel(tmp_path, *, omit=None, extra=None, mode=None, contents=None):
    path = tmp_path / f"{PREFIX}-py3-none-any.whl"
    names = sorted(name for name in TRACKED if name.startswith("dspy_security_bench/"))
    names += [f"{PREFIX}.dist-info/{name}" for name in (
        "METADATA", "WHEEL", "RECORD", "entry_points.txt", "licenses/LICENSE", "licenses/NOTICE"
    )]
    if omit:
        names.remove(omit)
    prefix = f"{PREFIX}.dist-info/"
    data = {
        prefix + "METADATA": b"Metadata-Version: 2.5\nName: dspy-security-bench\nVersion: 0.19.0\nRequires-Python: >=3.10\n\n",
        prefix + "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
        prefix + "entry_points.txt": ("[console_scripts]\n" + "\n".join(
            key + " = " + value for key, value in inventory.EXPECTED_SCRIPTS.items()) + "\n").encode(),
    }
    data.update(contents or {})
    if prefix + "RECORD" not in data:
        record = io.StringIO(newline="")
        writer = csv.writer(record)
        for name in names:
            payload = data.get(name, b"")
            digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
            writer.writerow([name, "", ""] if name == prefix + "RECORD" else [name, "sha256=" + digest, len(payload)])
        data[prefix + "RECORD"] = record.getvalue().encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, data.get(name, b""))
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
    for name in TRACKED - {"pyproject.toml"}:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"")
    monkeypatch.setattr(inventory.subprocess, "check_output", lambda *a, **k: "\0".join(TRACKED).encode())
    dist = tmp_path / "dist"
    dist.mkdir()
    sdist(dist, contents={"pyproject.toml": (tmp_path / "pyproject.toml").read_bytes()})
    wheel(dist)
    (dist / ".gitignore").write_bytes(marker)
    assert inventory.main([str(dist)]) == expected


@pytest.mark.parametrize("builder", [sdist, wheel])
def test_existing_source_path_with_substituted_bytes_is_rejected(tmp_path, builder):
    import hashlib

    expected = {name: hashlib.sha256(b"").hexdigest() for name in TRACKED}
    path = builder(tmp_path, contents={"dspy_security_bench/__init__.py": b"unexpected code"})
    with pytest.raises(ValueError, match="source bytes differ"):
        check_archive(path, TRACKED, "0.19.0", expected)


@pytest.mark.parametrize("builder", [sdist, wheel])
def test_matching_source_bytes_are_accepted(tmp_path, builder):
    import hashlib

    expected = {name: hashlib.sha256(b"").hexdigest() for name in TRACKED}
    assert check_archive(builder(tmp_path), TRACKED, "0.19.0", expected) > 0


def test_wheel_license_bytes_are_checked(tmp_path):
    import hashlib

    expected = {name: hashlib.sha256(b"").hexdigest() for name in TRACKED}
    path = wheel(tmp_path, contents={f"{PREFIX}.dist-info/licenses/LICENSE": b"wrong license"})
    with pytest.raises(ValueError, match="source bytes differ"):
        check_archive(path, TRACKED, "0.19.0", expected)


def test_source_snapshot_refuses_symlink_parent(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "file.py").write_text("source")
    (tmp_path / "link").symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic links"):
        inventory.source_digests(tmp_path, {"link/file.py"})


@pytest.mark.parametrize("kind", ["missing", "extra", "duplicate", "hash", "size", "empty-hash", "self-hash", "algorithm", "unsafe"])
def test_wheel_record_must_exactly_bind_every_member(tmp_path, kind):
    record_path = f"{PREFIX}.dist-info/RECORD"
    with zipfile.ZipFile(wheel(tmp_path)) as archive:
        rows = list(csv.reader(io.StringIO(archive.read(record_path).decode())))
    if kind == "missing":
        rows.pop(0)
    elif kind == "extra":
        rows.append(["not-in-wheel.py", "sha256=unknown", "0"])
    elif kind == "duplicate":
        rows.append(rows[0])
    elif kind == "hash":
        rows[0][1] = "sha256=" + "0" * 43
    elif kind == "size":
        rows[0][2] = "999"
    elif kind == "empty-hash":
        rows[0][1] = ""
    elif kind == "self-hash":
        next(row for row in rows if row[0] == record_path)[1] = "sha256=not-allowed"
    elif kind == "algorithm":
        rows[0][1] = rows[0][1].replace("sha256=", "sha1=")
    else:
        rows[0][0] = "../outside.py"
    result = io.StringIO(newline="")
    csv.writer(result).writerows(rows)
    with pytest.raises(ValueError, match="RECORD"):
        check_archive(wheel(tmp_path, contents={record_path: result.getvalue().encode()}), TRACKED, "0.19.0")


@pytest.mark.parametrize("record", [b'"unterminated', b"\xff", b"one,two\n", b"one,two,three,four\n"])
def test_wheel_record_rejects_ambiguous_csv(tmp_path, record):
    with pytest.raises(ValueError, match="RECORD"):
        check_archive(wheel(tmp_path, contents={f"{PREFIX}.dist-info/RECORD": record}), TRACKED, "0.19.0")


@pytest.mark.parametrize("header,replacement", [
    ("Name: dspy-security-bench", "Name: other-project"),
    ("Name: dspy-security-bench", "Name: dspy-security-bench\nName: dspy-security-bench"),
    ("Version: 0.19.0", "Version: 0.20.0"),
    ("Requires-Python: >=3.10", "Requires-Python: >=3.14"),
])
def test_rehashed_metadata_cannot_substitute_release_identity(tmp_path, header, replacement):
    member = f"{PREFIX}.dist-info/METADATA"
    with zipfile.ZipFile(wheel(tmp_path)) as archive:
        changed = archive.read(member).decode().replace(header, replacement).encode()
    with pytest.raises(ValueError, match="identity"):
        check_archive(wheel(tmp_path, contents={member: changed}), TRACKED, "0.19.0")


@pytest.mark.parametrize("header,replacement", [
    ("Wheel-Version: 1.0", "Wheel-Version: 2.0"),
    ("Root-Is-Purelib: true", "Root-Is-Purelib: false"),
    ("Tag: py3-none-any", "Tag: py3-none-win32"),
    ("Tag: py3-none-any", "Tag: py3-none-any\nTag: py3-none-any"),
    ("Tag: py3-none-any", "Tag: py3-none-any\nBuild: 1"),
])
def test_wheel_install_profile_must_match_its_filename(tmp_path, header, replacement):
    member = f"{PREFIX}.dist-info/WHEEL"
    with zipfile.ZipFile(wheel(tmp_path)) as archive:
        changed = archive.read(member).decode().replace(header, replacement).encode()
    with pytest.raises(ValueError, match="install metadata"):
        check_archive(wheel(tmp_path, contents={member: changed}), TRACKED, "0.19.0")


@pytest.mark.parametrize("entries", [
    b"[console_scripts]\ndspy-security-bench = unexpected:run\n",
    b"[console_scripts]\ndspy-security-bench = first:run\ndspy-security-bench = second:run\n",
    b"[console_scripts]\n[console_scripts]\n",
    b"\xff", b"no-section",
])
def test_rehashed_entrypoints_cannot_redirect_installed_commands(tmp_path, entries):
    with pytest.raises(ValueError, match="entry points"):
        check_archive(wheel(tmp_path, contents={f"{PREFIX}.dist-info/entry_points.txt": entries}), TRACKED, "0.19.0")


def test_metadata_resource_limit_is_enforced_before_parsing(tmp_path, monkeypatch):
    path = wheel(tmp_path)
    monkeypatch.setattr(inventory, "MAX_METADATA_BYTES", 10)
    with pytest.raises(ValueError, match="limit"):
        check_archive(path, TRACKED, "0.19.0")


def test_release_script_contract_matches_reviewed_pyproject():
    import re
    from pathlib import Path

    project = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    section = project.split("[project.scripts]\n", 1)[1].split("\n[", 1)[0]
    actual = dict(re.findall(r'^([a-z-]+) = "([^"]+)"$', section, re.M))
    assert actual == inventory.EXPECTED_SCRIPTS
    assert 'requires-python = ">=3.10"' in project
