"""Portable preflight for exclusive output creation, including Windows CRT links."""

import builtins

import pytest

from dspy_security_bench.outputio import write_new_file


@pytest.mark.parametrize("kind", ["file", "directory", "dangling", "linked"])
def test_existing_entries_are_rejected_before_platform_open(tmp_path, monkeypatch, kind):
    output = tmp_path / "output"
    target = tmp_path / "target"
    if kind == "file":
        output.write_bytes(b"KEEP")
    elif kind == "directory":
        output.mkdir()
    else:
        if kind == "linked":
            target.write_bytes(b"KEEP")
        try:
            output.symlink_to(target)
        except OSError:
            pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(builtins, "open", lambda *a, **k: pytest.fail("platform open must not see an existing entry"))
    with pytest.raises(FileExistsError):
        write_new_file(output, b"CHANGE")
    if kind == "dangling":
        assert not target.exists() and output.is_symlink()


def test_new_file_keeps_exact_bytes(tmp_path):
    output = tmp_path / "new"
    write_new_file(output, b"\x00\r\n\xff")
    assert output.read_bytes() == b"\x00\r\n\xff"


def test_failed_metadata_lookup_does_not_open_file(tmp_path, monkeypatch):
    def denied(*a, **k):
        raise PermissionError("metadata denied")
    output = tmp_path / "new"
    monkeypatch.setattr(type(output), "lstat", denied)
    monkeypatch.setattr(builtins, "open", lambda *a, **k: pytest.fail("metadata failure must not attempt open"))
    with pytest.raises(PermissionError):
        write_new_file(output, b"CHANGE")
