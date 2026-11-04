"""All-file preview, conflict refusal, and failure-aware scaffold application."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest

from dspy_security_bench.integrations import scaffold_io
from dspy_security_bench.integrations.catalog import FRAMEWORKS, get_framework
from dspy_security_bench.integrations.cli import integrate_main
from dspy_security_bench.integrations.doctor import run_doctor
from dspy_security_bench.integrations.identifiers import valid_target
from dspy_security_bench.integrations.scaffold import (
    MANIFEST_PATH,
    integrate_project,
    plan_integration,
)


def plan(root, **kwargs):
    return plan_integration(get_framework("mcp"), root, runner="missing:run", **kwargs)


def integrate(root, **kwargs):
    return integrate_project(get_framework("mcp"), root, runner="missing:run", **kwargs)


@pytest.mark.parametrize("framework", FRAMEWORKS, ids=lambda spec: spec.key)
def test_preview_is_complete_nonexecuting_and_agrees_with_written_bytes(tmp_path, framework):
    root = tmp_path / "not-created"
    preview = plan_integration(framework, root, runner="not_installed:run" if framework.key == "mcp" else None)
    assert not root.exists()
    assert len(preview.files) == 4 and preview.files[-1].relative == MANIFEST_PATH
    assert all(item.action == "create" for item in preview.files)
    for item in preview.files:
        if item.relative.suffix == ".py":
            ast.parse(item.content)
    result = scaffold_io.apply_plan(preview)
    assert len(result.created) == 4 and not result.conflicts and not result.replaced
    for item in preview.to_dict()["files"]:
        raw = (root / item["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == item["proposed_sha256"]
        assert len(raw) == item["proposed_size_bytes"]
    report = run_doctor(root, manifest_only=True)
    assert report.passed and not report.target_import_attempted


def test_changed_adapter_blocks_all_other_creation_without_force(tmp_path):
    target = tmp_path / "dspy_security_target.py"
    target.write_text("# my reviewed adapter\n")
    preview = plan(tmp_path)
    assert preview.has_conflicts
    result = integrate(tmp_path)
    assert not result.created and not result.replaced
    assert result.conflicts == (target,)
    assert sorted(path.name for path in tmp_path.iterdir()) == [target.name]
    assert target.read_text() == "# my reviewed adapter\n"


@pytest.mark.parametrize("relative", ["dspy_security_target.py", ".github/workflows/dspy-proofrun.yml",
                                      "tests/test_dspy_security_target.py", ".dspy-security-bench/integration.json"])
def test_a_conflict_at_any_selected_destination_stops_all_writes(tmp_path, relative):
    existing = tmp_path / relative
    existing.parent.mkdir(parents=True, exist_ok=True)
    existing.write_bytes(b"owner customization")
    before = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    result = integrate(tmp_path)
    assert result.conflicts == (existing,) and not result.created and not result.replaced
    assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == before
    assert existing.read_bytes() == b"owner customization"


def test_exact_reapplication_is_idempotent_even_with_force(tmp_path):
    initial = integrate(tmp_path)
    snapshots = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in initial.created}
    for force in (False, True):
        result = integrate(tmp_path, force=force)
        assert not result.created and not result.replaced and not result.conflicts
        assert set(result.skipped) == set(initial.created)
        assert {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in initial.created} == snapshots


def test_force_replaces_only_different_selected_files_and_does_not_mutate_hard_links(tmp_path):
    target = tmp_path / "dspy_security_target.py"
    other = tmp_path / "keep.py"
    target.write_bytes(b"# user adapter\n")
    try:
        os.link(target, other)
    except OSError:
        pytest.skip("filesystem cannot create hard links")
    preview = plan(tmp_path, force=True)
    assert preview.files[0].action == "replace"
    result = scaffold_io.apply_plan(preview)
    assert result.replaced == (target,) and len(result.created) == 3
    assert other.read_bytes() == b"# user adapter\n"
    assert target.read_bytes() == preview.files[0].content
    assert not list(tmp_path.glob(".dsb-scaffold-*"))


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("kind", ["file-link", "dangling-link", "parent-link", "parent-file", "directory", "fifo", "oversized"])
def test_unsafe_destinations_fail_before_any_writes(tmp_path, force, kind):
    path = tmp_path / "dspy_security_target.py"
    if "link" in kind:
        actual = tmp_path / "actual"
        actual.mkdir()
        (actual / "target.py").write_text("# keep")
        try:
            if kind == "parent-link":
                (tmp_path / ".dspy-security-bench").symlink_to(actual, target_is_directory=True)
            else:
                path.symlink_to(actual / ("missing" if kind == "dangling-link" else "target.py"))
        except OSError:
            pytest.skip("symlinks unavailable")
    elif kind == "parent-file":
        (tmp_path / ".github").write_bytes(b"keep")
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO unavailable")
        os.mkfifo(path)
    else:
        path.write_bytes(b"x" * (scaffold_io.MAX_EXISTING_BYTES + 1))
    before = sorted(str(item.relative_to(tmp_path)) for item in tmp_path.rglob("*"))
    with pytest.raises(ValueError):
        integrate(tmp_path, force=force)
    assert sorted(str(item.relative_to(tmp_path)) for item in tmp_path.rglob("*")) == before
    if "link" in kind:
        assert (actual / "target.py").read_text() == "# keep"
        assert not (actual / "missing").exists()


@pytest.mark.parametrize("module", ["class", "package.class", "a²", "target_K", "a" * 250, "a/b", "CON", "pkg.LPT1", "tests.test_dspy_security_target", "TESTS.test_dspy_security_target", "tests.test_dspy_security_target.child"])
def test_invalid_or_colliding_modules_never_create_root(tmp_path, module):
    root = tmp_path / "new"
    with pytest.raises(ValueError):
        integrate(root, module=module)
    assert not root.exists()


@pytest.mark.parametrize("target", ["class:run", "pkg:class", "pkg.a²:run", "pkg:run_K", "pkg:x.y", "pkg:" + "x" * 255])
def test_shared_identifier_contract_rejects_invalid_generated_imports(target):
    assert not valid_target(target)


@pytest.mark.parametrize("runner", ["class:run", "pkg:class", "pkg:run_K", "pkg:" + "x" * 255])
def test_invalid_callback_stops_before_generation(tmp_path, runner):
    root = tmp_path / "new"
    with pytest.raises(ValueError):
        integrate_project(get_framework("mcp"), root, runner=runner)
    assert not root.exists()


@pytest.mark.parametrize("runner", ["dspy_security_target:run", "DSPY_SECURITY_TARGET:run", "dspy_security_target.child:run",
                                   "tests.test_dspy_security_target:run"])
def test_generated_modules_cannot_overwrite_or_shadow_callback_source(tmp_path, runner):
    root = tmp_path / "new"
    with pytest.raises(ValueError, match="callback module collides"):
        integrate_project(get_framework("mcp"), root, runner=runner, force=True)
    assert not root.exists()


@pytest.mark.parametrize("model", ["", "secret\nvalue", "x" * 513, False])
def test_model_validation_agrees_with_manifest_contract(tmp_path, model):
    root = tmp_path / "new"
    with pytest.raises(ValueError):
        integrate_project(get_framework("langchain"), root, model=model)
    assert not root.exists()


def test_custom_catalog_injection_and_nonboolean_options_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        plan_integration(replace(get_framework("mcp"), adapter="injected source"), tmp_path)
    with pytest.raises(ValueError):
        plan(tmp_path, force="yes")


def test_selected_outputs_only_and_unicode_identifier(tmp_path):
    preview = plan(tmp_path, module="nested.target_é", include_test=False, include_workflow=False)
    assert [item.relative.as_posix() for item in preview.files] == ["nested/target_é.py", MANIFEST_PATH.as_posix()]
    scaffold_io.apply_plan(preview)
    assert not (tmp_path / ".github").exists() and not (tmp_path / "tests").exists()
    assert run_doctor(tmp_path, manifest_only=True).passed


def test_changed_snapshot_stops_before_any_output(tmp_path):
    target = tmp_path / "dspy_security_target.py"
    target.write_bytes(b"old")
    preview = plan(tmp_path, force=True)
    target.write_bytes(b"new owner change")
    with pytest.raises(ValueError, match="changed after planning"):
        scaffold_io.apply_plan(preview)
    assert target.read_bytes() == b"new owner change"
    assert not (tmp_path / MANIFEST_PATH).exists() and not (tmp_path / ".github").exists()


def test_late_change_retains_partial_outputs_and_manifest_is_last(tmp_path, monkeypatch):
    preview = plan(tmp_path)
    original = scaffold_io.write_new_file

    def concurrent_creation(path, raw):
        original(path, raw)
        if path.name == "dspy_security_target.py":
            workflow = tmp_path / ".github/workflows/dspy-proofrun.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_bytes(b"owner created this")

    monkeypatch.setattr(scaffold_io, "write_new_file", concurrent_creation)
    with pytest.raises(scaffold_io.ScaffoldWriteError) as error:
        scaffold_io.apply_plan(preview)
    assert error.value.completed == (Path("dspy_security_target.py"),)
    assert (tmp_path / ".github/workflows/dspy-proofrun.yml").read_bytes() == b"owner created this"
    assert not (tmp_path / MANIFEST_PATH).exists()


def test_exclusive_create_rejects_late_file_without_truncation(tmp_path, monkeypatch):
    original = scaffold_io.write_new_file

    def create_first(path, raw):
        path.write_bytes(b"owner won the create")
        original(path, raw)

    monkeypatch.setattr(scaffold_io, "write_new_file", create_first)
    with pytest.raises(scaffold_io.ScaffoldWriteError):
        integrate(tmp_path)
    assert (tmp_path / "dspy_security_target.py").read_bytes() == b"owner won the create"
    assert not (tmp_path / MANIFEST_PATH).exists()


def test_failed_replace_preserves_original_and_cleans_only_owned_staging(tmp_path, monkeypatch):
    target = tmp_path / "dspy_security_target.py"
    target.write_bytes(b"keep me")

    def fail(*args):
        raise OSError("SECRET-DETAIL")

    monkeypatch.setattr(scaffold_io.os, "replace", fail)
    with pytest.raises(scaffold_io.ScaffoldWriteError) as error:
        integrate(tmp_path, force=True)
    assert "SECRET-DETAIL" not in str(error.value)
    assert target.read_bytes() == b"keep me"
    assert not list(tmp_path.glob(".dsb-scaffold-*"))
    assert error.value.completed == ()


def test_failed_staging_write_does_not_truncate_original(tmp_path, monkeypatch):
    target = tmp_path / "dspy_security_target.py"
    target.write_bytes(b"owner work")
    original = scaffold_io.os.fdopen

    class ShortWrite:
        def __init__(self, descriptor, mode):
            self.stream = original(descriptor, mode)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def write(self, raw):
            return self.stream.write(raw[:1])

    monkeypatch.setattr(scaffold_io.os, "fdopen", lambda descriptor, mode, **kwargs:
                        ShortWrite(descriptor, mode) if mode == "wb" else original(descriptor, mode, **kwargs))
    with pytest.raises(scaffold_io.ScaffoldWriteError):
        integrate(tmp_path, force=True)
    assert target.read_bytes() == b"owner work"
    assert not list(tmp_path.glob(".dsb-scaffold-*"))


def test_failed_staging_stream_closes_descriptor_and_preserves_original(tmp_path, monkeypatch):
    target = tmp_path / "dspy_security_target.py"
    target.write_bytes(b"owner work")
    fdopen, mkstemp = scaffold_io.os.fdopen, scaffold_io.tempfile.mkstemp
    descriptors = []

    def track_staging(**kwargs):
        descriptor, name = mkstemp(**kwargs)
        descriptors.append(descriptor)
        return descriptor, name

    def fail_stream(descriptor, mode, **kwargs):
        if mode == "wb":
            raise OSError("staging stream failure")
        return fdopen(descriptor, mode, **kwargs)

    monkeypatch.setattr(scaffold_io.tempfile, "mkstemp", track_staging)
    monkeypatch.setattr(scaffold_io.os, "fdopen", fail_stream)
    with pytest.raises(scaffold_io.ScaffoldWriteError):
        integrate(tmp_path, force=True)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert target.read_bytes() == b"owner work"
    assert not list(tmp_path.glob(".dsb-scaffold-*"))


@pytest.mark.parametrize("callback_name", ["build_agent", "CallbackAdapter", "_run_callback"])
def test_callback_binding_cannot_be_shadowed_by_generated_names(tmp_path, monkeypatch, callback_name):
    module = ModuleType("synthetic_callbacks")
    setattr(module, callback_name, lambda query, tools, system_directive: "called the original callback")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    preview = plan_integration(get_framework("mcp"), tmp_path, runner=f"{module.__name__}:{callback_name}")
    namespace = {}
    # Execute only this deliberately synthetic test fixture; planning itself
    # never imports the callback or executes generated source.
    exec(preview.files[0].content, namespace)
    result = namespace["build_agent"]().run("synthetic query", [])
    assert result.final_answer == "called the original callback"


def test_cli_preview_conflict_and_explicit_replacement(tmp_path, capsys):
    root = tmp_path / "new"
    args = ["--root", str(root), "--framework", "mcp", "--runner", "missing:run"]
    assert integrate_main([*args, "--dry-run", "--json"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["mode"] == "scaffold_preview" and not preview["has_conflicts"]
    assert not root.exists()
    root.mkdir()
    target = root / "dspy_security_target.py"
    target.write_bytes(b"SECRET-CONTENT")
    assert integrate_main([*args, "--dry-run", "--json"]) == 1
    output = capsys.readouterr().out
    assert "SECRET-CONTENT" not in output and json.loads(output)["has_conflicts"]
    assert integrate_main(args) == 1
    assert "no files written" in capsys.readouterr().err
    assert not (root / MANIFEST_PATH).exists()
    assert integrate_main([*args, "--force", "--dry-run"]) == 0
    assert "replace" in capsys.readouterr().out and target.read_bytes() == b"SECRET-CONTENT"
    assert integrate_main([*args, "--force"]) == 0
    assert "replaced" in capsys.readouterr().out
    assert integrate_main(args) == 0
    assert "unchanged" in capsys.readouterr().out


def test_auto_detection_preview_emits_only_json(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("langchain\n")
    assert integrate_main(["--root", str(tmp_path), "--dry-run", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "scaffold_preview"
    assert not (tmp_path / MANIFEST_PATH).exists()


def test_cli_write_failure_explains_partial_state_without_source_exception(tmp_path, capsys, monkeypatch):
    def fail(*args):
        raise OSError("SECRET-DETAIL")

    monkeypatch.setattr(scaffold_io, "write_new_file", fail)
    assert integrate_main(["--root", str(tmp_path), "--framework", "mcp", "--runner", "missing:run"]) == 2
    output = capsys.readouterr().err
    assert "no rollback" in output and "attempted" in output and "SECRET-DETAIL" not in output
