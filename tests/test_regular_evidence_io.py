"""Local evidence intake must reject special files without waiting for a writer."""

import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from dspy_security_bench import jsonio
from dspy_security_bench.cli import main


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named pipe only")
def test_shared_snapshot_reader_rejects_fifo_without_waiting(tmp_path):
    path = tmp_path / "PRIVATE-evidence.json"
    os.mkfifo(path)
    code = """
import sys
from pathlib import Path
from dspy_security_bench.jsonio import read_json_snapshot
try:
    read_json_snapshot(Path(sys.argv[1]), 100)
except (ValueError, OSError):
    print("rejected")
    raise SystemExit(2)
raise SystemExit(0)
"""
    # subprocess.run kills and reaps a stalled child on timeout, including on
    # the vulnerable baseline; this regression cannot hang the test session.
    result = subprocess.run([sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=3, check=False)
    assert result.returncode == 2 and result.stdout.strip() == "rejected"
    assert "PRIVATE" not in result.stdout + result.stderr


@pytest.mark.parametrize("maximum", [True, 0, -1, 1.0, "PRIVATE", None])
def test_bad_limit_fails_before_path_access(maximum, monkeypatch):
    monkeypatch.setattr(Path, "lstat", lambda *a: pytest.fail("invalid budget accessed input"))
    with pytest.raises(ValueError) as caught:
        jsonio.read_regular_bytes(Path("PRIVATE"), maximum)
    assert "PRIVATE" not in str(caught.value)


def test_exact_bytes_and_overflow_probe_are_preserved(tmp_path):
    path = tmp_path / "ordinary.json"
    raw = b' { "value" : "caf\xc3\xa9", "flag":false }\r\n'
    path.write_bytes(raw)
    assert jsonio.read_regular_bytes(path, len(raw)) == raw
    assert jsonio.read_regular_bytes(str(path), 5) == raw[:6]
    assert jsonio.read_json_snapshot(path, len(raw)) == (raw, {"value": "café", "flag": False})
    with pytest.raises(ValueError, match="exceeds"):
        jsonio.read_json_snapshot(path, len(raw) - 1)


@pytest.mark.parametrize("mode", [stat.S_IFDIR, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFLNK])
def test_nonregular_types_are_rejected_before_os_open(tmp_path, mode, monkeypatch):
    path = tmp_path / "ordinary.json"
    path.write_bytes(b"{}")
    monkeypatch.setattr(Path, "lstat", lambda *a: SimpleNamespace(st_mode=mode))
    monkeypatch.setattr(jsonio.os, "open", lambda *a: pytest.fail("special input was opened"))
    with pytest.raises(ValueError, match="regular"):
        jsonio.read_regular_bytes(path, 100)


@pytest.mark.parametrize("phase", ["before", "opened"])
def test_observed_windows_reparse_points_rejected_on_any_host(tmp_path, phase, monkeypatch):
    path = tmp_path / "ordinary.json"
    path.write_bytes(b"{}")
    monkeypatch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024, raising=False)
    fake = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=1024)
    if phase == "before":
        monkeypatch.setattr(Path, "lstat", lambda *a: fake)
        monkeypatch.setattr(jsonio.os, "open", lambda *a: pytest.fail("reparse input was opened"))
    else:
        monkeypatch.setattr(jsonio.os, "fstat", lambda *a: fake)
        monkeypatch.setattr(jsonio.os, "fdopen", lambda *a, **k: pytest.fail("reparse descriptor was read"))
    with pytest.raises(ValueError, match="regular"):
        jsonio.read_regular_bytes(path, 100)


@pytest.mark.parametrize("failure", ["none", "stat", "read"])
def test_descriptors_are_closed_on_every_opened_path(tmp_path, failure, monkeypatch):
    path = tmp_path / "ordinary.json"
    path.write_bytes(b"{}")
    opened = []
    real_open, real_stat = os.open, os.fstat

    def capture(source, flags):
        descriptor = real_open(source, flags)
        assert not os.get_inheritable(descriptor)
        opened.append(descriptor)
        return descriptor

    def fail(*args, **kwargs):
        raise OSError("PRIVATE filesystem diagnostic")

    monkeypatch.setattr(jsonio.os, "open", capture)
    if failure == "stat":
        monkeypatch.setattr(jsonio.os, "fstat", fail)
    elif failure == "read":
        monkeypatch.setattr(jsonio.os, "fdopen", fail)
    if failure == "none":
        assert jsonio.read_regular_bytes(path, 100) == b"{}"
    else:
        with pytest.raises(ValueError) as caught:
            jsonio.read_regular_bytes(path, 100)
        assert "PRIVATE" not in str(caught.value)
    assert len(opened) == 1
    with pytest.raises(OSError):
        real_stat(opened[0])


def test_regular_replacement_at_open_is_rejected_when_identity_available(tmp_path, monkeypatch):
    path = tmp_path / "ordinary.json"
    replacement = tmp_path / "replacement.json"
    path.write_bytes(b'{"old":true}')
    replacement.write_bytes(b'{"new":true}')
    if not path.stat().st_ino or not replacement.stat().st_ino:
        pytest.skip("filesystem does not expose stable inode identifiers")
    original = os.open

    def replace(source, flags):
        source.rename(tmp_path / "retained.json")
        replacement.rename(source)
        return original(source, flags)

    monkeypatch.setattr(jsonio.os, "open", replace)
    with pytest.raises(ValueError, match="changed while opening"):
        jsonio.read_regular_bytes(path, 100)


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="no atomic final-component no-follow flag")
def test_symlink_replacement_at_open_is_not_followed(tmp_path, monkeypatch):
    path, replacement = tmp_path / "ordinary.json", tmp_path / "replacement.json"
    path.write_bytes(b"{}")
    replacement.write_bytes(b'{"PRIVATE":true}')
    original = os.open

    def replace(source, flags):
        assert flags & os.O_NOFOLLOW
        source.unlink()
        source.symlink_to(replacement)
        return original(source, flags)

    monkeypatch.setattr(jsonio.os, "open", replace)
    with pytest.raises(ValueError) as caught:
        jsonio.read_regular_bytes(path, 100)
    assert "PRIVATE" not in str(caught.value)


def test_static_symlink_to_valid_json_is_rejected(tmp_path):
    path, link = tmp_path / "ordinary.json", tmp_path / "link.json"
    path.write_bytes(b"{}")
    try:
        link.symlink_to(path)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error.errno}")
    with pytest.raises(ValueError, match="regular"):
        jsonio.read_json_snapshot(link, 100)


def test_shared_reader_does_not_imply_ancestor_confinement(tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "ordinary.json").write_bytes(b"{}")
    link = tmp_path / "linked-directory"
    try:
        link.symlink_to(folder, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error.errno}")
    assert jsonio.read_json_object(link / "ordinary.json", 100) == {}


def test_regular_input_still_supported_without_optional_posix_flags(tmp_path, monkeypatch):
    path = tmp_path / "ordinary.json"
    path.write_bytes(b"{}")
    for flag in ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
        monkeypatch.delattr(jsonio.os, flag, raising=False)
    assert jsonio.read_json_object(path, 100) == {}


@pytest.mark.parametrize("command", [["scan", "verify"], ["defend", "verify"], ["collective", "plane", "verify"],
                                     ["causal", "verify-submission"], ["proofrun", "verify"]])
def test_nonordinary_cli_input_is_an_error_not_a_source_leak(tmp_path, command, capsys):
    path = tmp_path / "PRIVATE-directory.json"
    path.mkdir()
    assert main([*command, str(path)]) == 2
    captured = capsys.readouterr()
    assert "PRIVATE" not in captured.out + captured.err


def test_filesystem_permission_errors_withhold_private_path(tmp_path, monkeypatch):
    path = tmp_path / "PRIVATE.json"
    path.write_bytes(b"{}")

    def fail(*args, **kwargs):
        raise PermissionError(13, "PRIVATE", str(path))

    monkeypatch.setattr(jsonio.os, "open", fail)
    with pytest.raises(ValueError) as caught:
        jsonio.read_json_object(path, 100)
    assert "PRIVATE" not in str(caught.value)
