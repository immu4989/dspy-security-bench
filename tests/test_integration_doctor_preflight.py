"""Declarative onboarding must not confuse text matches with executable settings."""

import io
import json
import os
from types import SimpleNamespace

import pytest

from dspy_security_bench.cli import main
from dspy_security_bench.integrations import doctor
from dspy_security_bench.integrations.catalog import get_framework
from dspy_security_bench.integrations.preflight import MAX_CONTROL_BYTES
from dspy_security_bench.integrations.scaffold import (
    MANIFEST_PATH,
    WORKFLOW_PATH,
    integrate_project,
)


@pytest.fixture
def project(tmp_path):
    integrate_project(get_framework("mcp"), tmp_path, runner="custom:run")
    return tmp_path


def forbid(*a, **k):
    pytest.fail("declarative preflight must not reach target code or import hooks")


def check(report, name):
    return next(item for item in report.checks if item.name == name)


@pytest.mark.parametrize("raw", [b"[]", b"null", b'{"schema_version":1,"schema_version":1}',
                                b'{"schema_version":NaN}', b'{}', b'\xff', b'"text"'])
def test_invalid_manifest_stops_before_all_import_hooks(project, monkeypatch, raw):
    (project / MANIFEST_PATH).write_bytes(raw)
    monkeypatch.setattr(doctor, "_load_factory", forbid)
    monkeypatch.setattr(doctor.importlib.util, "find_spec", forbid)
    report = doctor.run_doctor(project)
    assert not report.passed and check(report, "manifest").status == "fail"
    assert not report.target_import_attempted and report.factory_calls_attempted == 0


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 1.0), ("required_import", "PRIVATE.parent"),
    ("required_env", "OPENAI_API_KEY"), ("required_env", ["GOOD", "GOOD"]),
    ("required_env", ["PRIVATE\nFORGED"]), ("required_env", [{}]),
    ("framework", []), ("framework", "PRIVATE-invalid"), ("agent", "PRIVATE;code:run"),
    ("agent", "module:run.more"), ("agent", "a" * 257 + ":run"), ("runner", 42),
    ("package_hint", "PRIVATE\x1b[2J"), ("model", {}), ("engine_ref", "main"),
    ("engine_ref", "PRIVATE\nref"), ("unexpected", "PRIVATE"),
])
def test_manifest_fields_are_typed_and_source_diagnostics_withheld(project, monkeypatch, field, value):
    path = project / MANIFEST_PATH
    manifest = json.loads(path.read_bytes())
    manifest[field] = value
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(doctor, "_load_factory", forbid)
    monkeypatch.setattr(doctor.importlib.util, "find_spec", forbid)
    result = doctor.run_doctor(project).to_dict()
    assert not result["passed"] and "PRIVATE" not in json.dumps(result)


def test_manifest_only_checks_neither_imports_factories_nor_environment(project, monkeypatch, capsys):
    path = project / MANIFEST_PATH
    manifest = json.loads(path.read_bytes())
    manifest["required_env"] = ["API_KEY"]
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(doctor, "_load_factory", forbid)
    monkeypatch.setattr(doctor, "detect_frameworks", forbid)
    monkeypatch.setattr(doctor.importlib.util, "find_spec", forbid)
    # Replace only doctor's os reference, not pytest's process environment.
    monkeypatch.setattr(doctor, "os", SimpleNamespace(environ=SimpleNamespace(get=forbid)))
    assert main(["doctor", "--root", str(project), "--manifest-only", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "manifest_only" and not result["target_import_attempted"]
    assert result["factory_calls_attempted"] == 0
    assert next(c for c in result["checks"] if c["name"] == "agent-contract")["status"] == "not_checked"
    text = doctor.render_doctor(doctor.run_doctor(project, manifest_only=True))
    assert "READY" not in text and "NOT CHECKED" in text


@pytest.mark.parametrize("change", ["comment_permissions", "job_override", "comment_agent", "wrong_engine",
                                  "duplicate", "merge", "cycle", "not_jobs", "wrong_job", "disabled"])
def test_workflow_semantics_not_comments_gate_target_execution(project, monkeypatch, change):
    path = project / WORKFLOW_PATH
    text = path.read_text()
    if change == "comment_permissions":
        text = text.replace("  id-token: write", "  # id-token: write").replace("  attestations: write", "  # attestations: write")
    elif change == "job_override":
        text = text.replace("  proofrun:\n", "  proofrun:\n    permissions:\n      contents: read\n")
    elif change == "comment_agent":
        text = text.replace("      agent: dspy_security_target:build_agent", "      # agent: dspy_security_target:build_agent\n      agent: wrong:target")
    elif change == "wrong_engine":
        text = text.replace("proofrun.yml@v0.19.0", "proofrun.yml@main")
    elif change == "duplicate":
        text += "\njobs: {}\n"
    elif change == "merge":
        text = "defaults: &defaults {a: b}\n" + text.replace("  proofrun:\n", "  proofrun:\n    <<: *defaults\n")
    elif change == "cycle":
        text = "cycle: &cycle [*cycle]\n" + text
    elif change == "not_jobs":
        text = "jobs: []\n"
    elif change == "wrong_job":
        text = text.replace("immu4989/dspy-security-bench/", "untrusted/example/")
    else:
        text = text.replace("  proofrun:\n", "  proofrun:\n    if: false\n")
    path.write_text(text)
    monkeypatch.setattr(doctor, "_load_factory", forbid)
    result = doctor.run_doctor(project)
    assert not result.passed and check(result, "workflow").status == "fail"
    assert not result.target_import_attempted


def test_job_permissions_override_restrictive_workflow_defaults(project):
    path = project / WORKFLOW_PATH
    text = path.read_text().replace("  id-token: write\n  attestations: write\n", "")
    path.write_text(text.replace("  proofrun:\n", "  proofrun:\n    permissions:\n      id-token: write\n      attestations: write\n"))
    result = doctor.run_doctor(project, manifest_only=True)
    assert result.passed and check(result, "workflow").status == "pass"


def test_sha_reference_distinguished_from_version_tag(project):
    manifest = json.loads((project / MANIFEST_PATH).read_bytes())
    manifest["engine_ref"] = "a" * 40
    (project / MANIFEST_PATH).write_text(json.dumps(manifest))
    workflow = project / WORKFLOW_PATH
    workflow.write_text(workflow.read_text().replace("v0.19.0", "a" * 40))
    assert check(doctor.run_doctor(project, manifest_only=True), "engine-ref").status == "pass"


@pytest.mark.parametrize("kind", ["manifest", "workflow"])
@pytest.mark.parametrize("problem", ["oversize", "link", "fifo"])
def test_control_files_are_bounded_regular_and_unlinked(project, monkeypatch, kind, problem):
    path = project / (MANIFEST_PATH if kind == "manifest" else WORKFLOW_PATH)
    if problem == "oversize":
        path.write_bytes(b" " * (MAX_CONTROL_BYTES + 1))
    else:
        retained = path.with_name("retained")
        path.rename(retained)
        if problem == "link":
            try:
                path.symlink_to(retained)
            except OSError:
                pytest.skip("symlink creation unavailable")
        elif hasattr(os, "mkfifo"):
            os.mkfifo(path)
        else:
            pytest.skip("FIFO unavailable")
    monkeypatch.setattr(doctor, "_load_factory", forbid)
    result = doctor.run_doctor(project)
    assert not result.passed and check(result, kind).status == "fail"


@pytest.mark.parametrize("bad", ["empty_name", "blank_name", "second_contract", "singleton", "exception"])
def test_runtime_checks_both_instances_and_hides_exception_content(project, monkeypatch, bad, capsys):
    calls = []
    shared = SimpleNamespace(name="agent", run=lambda: forbid())

    def factory():
        calls.append(1)
        print("PRIVATE target stdout")
        if bad == "exception":
            raise RuntimeError("PRIVATE credentials")
        if bad == "singleton":
            return shared
        if bad == "second_contract" and len(calls) == 2:
            return object()
        name = "" if bad == "empty_name" else " " if bad == "blank_name" else "agent"
        return SimpleNamespace(name=name, run=lambda: forbid())

    monkeypatch.setattr(doctor, "_load_factory", lambda *a: factory)
    result = doctor.run_doctor(project)
    assert not result.passed and result.target_import_attempted
    assert result.factory_calls_attempted == len(calls)
    assert check(result, "agent-contract").status == "fail"
    assert "PRIVATE" not in json.dumps(result.to_dict()) + capsys.readouterr().out


def test_standard_target_prints_do_not_break_json_output(project, monkeypatch, capsys):
    def factory():
        print("PRIVATE text")
        return SimpleNamespace(name="valid", run=forbid)
    monkeypatch.setattr(doctor, "_load_factory", lambda *a: factory)
    assert main(["doctor", "--root", str(project), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["factory_calls_attempted"] == 2 and result["passed"]


def test_discard_does_not_buffer_target_output():
    stream = doctor._Discard()
    assert isinstance(stream, io.TextIOBase) and stream.write("x" * 1_000_000) == 1_000_000
    assert not hasattr(stream, "getvalue")


def test_workflow_loader_does_not_change_global_yaml_boolean_rules(project):
    import yaml

    from dspy_security_bench.scan.yaml_config import ConfigLoader
    assert doctor.run_doctor(project, manifest_only=True).passed
    assert yaml.safe_load("value: on")["value"] is True
    assert yaml.load("value: on", Loader=ConfigLoader)["value"] is True


@pytest.mark.parametrize("framework", ["openai-agents", "langchain", "pydantic-ai", "crewai", "autogen", "mcp"])
def test_all_generated_frameworks_have_a_declarative_path_without_sdks(tmp_path, monkeypatch, framework):
    integrate_project(get_framework(framework), tmp_path, runner="callback:run" if framework == "mcp" else None)
    monkeypatch.setattr(doctor, "_load_factory", forbid)
    monkeypatch.setattr(doctor.importlib.util, "find_spec", forbid)
    result = doctor.run_doctor(tmp_path, manifest_only=True)
    assert result.passed and not result.target_import_attempted


@pytest.mark.parametrize("raw", ["x: " + "[" * 51 + "0" + "]" * 51,
                                "x: !!python/object/apply:os.system ['PRIVATE']",
                                "x: " + "1" * 129, "x: .nan"])
def test_unsupported_workflow_values_fail_without_target_loading(project, monkeypatch, raw):
    path = project / WORKFLOW_PATH
    path.write_text(path.read_text() + "\n" + raw + "\n")
    monkeypatch.setattr(doctor, "_load_factory", forbid)
    result = doctor.run_doctor(project)
    assert not result.passed and "PRIVATE" not in json.dumps(result.to_dict())


def test_unicode_identifier_supported_by_scaffold_remains_valid(tmp_path):
    integrate_project(get_framework("mcp"), tmp_path, runner="callback:run", module="target_é")
    assert doctor.run_doctor(tmp_path, manifest_only=True).passed


def test_linked_control_parent_is_rejected(project, monkeypatch):
    parent = project / ".dspy-security-bench"
    retained = project / "retained"
    parent.rename(retained)
    try:
        parent.symlink_to(retained, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(doctor, "_load_factory", forbid)
    assert not doctor.run_doctor(project).passed
