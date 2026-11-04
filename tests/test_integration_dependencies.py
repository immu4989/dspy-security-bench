"""Detection is a static declaration inventory, never a project execution step."""

from __future__ import annotations

import json
import os

import pytest

from dspy_security_bench.integrations import dependencies as intake
from dspy_security_bench.integrations.catalog import detect_frameworks, get_framework
from dspy_security_bench.integrations.cli import integrate_main
from dspy_security_bench.integrations.doctor import run_doctor
from dspy_security_bench.integrations.scaffold import integrate_project
from dspy_security_bench.trace.runtime import runtime_doctor


def detected(root):
    return [(spec.key, paths) for spec, paths in detect_frameworks(root)]


@pytest.mark.parametrize(("filename", "source", "framework"), [
    ("pyproject.toml", '[project]\ndependencies=["LangGraph[all]>=1; python_version < \'3.0\'"]', "langchain"),
    ("pyproject.toml", '[project.optional-dependencies]\nagent=["openai_agents>=0.1"]', "openai-agents"),
    ("pyproject.toml", '[dependency-groups]\nagent=["pydantic.ai"]\ntest=[{include-group="agent"}]', "pydantic-ai"),
    ("pyproject.toml", '[tool.poetry.dependencies]\npython="^3.12"\ncrewai="^1"', "crewai"),
    ("pyproject.toml", '[tool.poetry.group.agent.dependencies]\nautogen-agentchat={version="^0.7", optional=true}', "autogen"),
    ("pyproject.toml", '[tool.poetry.dev-dependencies]\nfastmcp=[{version="^2", python="^3.12"}]', "mcp"),
    ("Pipfile", '[packages]\nlangchain={git="https://example.invalid/crewai", ref="main"}', "langchain"),
    ("Pipfile", '[dev-packages]\nopenai-agents="*"', "openai-agents"),
    ("Pipfile", '[agent-tests]\ncrewai={path="./langchain"}', "crewai"),
    ("setup.cfg", '[options]\ninstall_requires =\n    pydantic_ai>=1\n    requests', "pydantic-ai"),
    ("setup.cfg", '[options.extras_require]\nagent =\n    pyautogen; python_version < "3.0"', "autogen"),
    ("setup.py", 'from setuptools import setup as configure\nconfigure(install_requires=["crewai"])', "crewai"),
    ("setup.py", 'import setuptools as s\ns.setup(extras_require={"agent": ("fastmcp",)})', "mcp"),
    ("setup.py", 'import distutils.core\ndistutils.core.setup(install_requires=("langgraph",))', "langchain"),
    ("requirements-dev.txt", "Pydantic.AI>=1\n", "pydantic-ai"),
    ("requirements.txt", 'openai-agents @ https://example.invalid/crewai.whl#sha256=123\n', "openai-agents"),
    ("requirements.txt", 'langchain@https://example.invalid/crewai.whl\n', "langchain"),
    ("requirements.txt", 'langchain[openai] >=1; python_version < "3.0" # crewai\n', "langchain"),
    ("requirements.txt", "langchain==1 \\\n  --hash=sha256:123 \\\n  --hash sha256:456\n", "langchain"),
])
def test_supported_static_declarations(tmp_path, filename, source, framework):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    assert detected(tmp_path) == [(framework, (filename,))]


@pytest.mark.parametrize(("filename", "source"), [
    ("pyproject.toml", '# crewai\n[project]\nname="langchain"\ndescription="mcp"\ndependencies=["requests"]\n[tool.example]\nframework="openai-agents"'),
    ("pyproject.toml", '[build-system]\nrequires=["crewai"]\n[tool.uv]\nconstraint-dependencies=["langchain"]'),
    ("Pipfile", '[scripts]\ncheck="crewai --help"\n[[source]]\nname="langchain"\nurl="https://example.invalid/openai-agents"'),
    ("requirements.txt", '# langchain\n--index-url https://example.invalid/crewai\n--find-links https://example.invalid/mcp\nrequests @ https://example.invalid/openai-agents.whl\n'),
    ("setup.cfg", '[metadata]\nname = crewai\n[options]\ninstall_requires = requests\nsetup_requires = langchain'),
    ("setup.py", 'from setuptools import setup\nsetup(name="crewai", description="langchain", install_requires=["requests"])'),
    ("requirements.txt", "langchain-core\nnot-crewai\nfastmcp-helper\n"),
])
def test_comments_metadata_urls_build_requirements_and_partial_names_do_not_match(tmp_path, filename, source):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    (tmp_path / "uv.lock").write_text('name="pydantic-ai"', encoding="utf-8")
    (tmp_path / "Pipfile.lock").write_text('{"crewai": "1"}', encoding="utf-8")
    assert detected(tmp_path) == []


def test_local_includes_constraints_dedup_and_evidence(tmp_path):
    (tmp_path / "reqs").mkdir()
    (tmp_path / "requirements.txt").write_text('-r reqs/base.in\n--requirement="reqs/base.in"\n-c requirements-constraints.txt\n-c https://example.invalid/secret\n')
    (tmp_path / "requirements-constraints.txt").write_text("crewai==1\n")
    (tmp_path / "reqs/base.in").write_text("langgraph>=1\n--constraint missing.txt\n")
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["langchain"]')
    assert detected(tmp_path) == [("langchain", ("pyproject.toml", "reqs/base.in"))]
    (tmp_path / "requirements-dev.txt").write_text("-r requirements-constraints.txt\n")
    assert detected(tmp_path) == [("langchain", ("pyproject.toml", "reqs/base.in")), ("crewai", ("requirements-constraints.txt",))]


def test_constraint_only_reference_is_not_read(tmp_path):
    (tmp_path / "requirements.txt").write_text("langchain\n-c secret-constraints.in\n")
    (tmp_path / "secret-constraints.in").write_bytes(b"not utf8 \xff")
    assert detected(tmp_path) == [("langchain", ("requirements.txt",))]


@pytest.mark.parametrize("source", [
    '[project]\ndependencies="crewai"',
    '[project]\ndependencies=[true]',
    '[project]\ndependencies=["crewai"]\ndependencies=["langchain"]',
    '[project.optional-dependencies]\nx="crewai"',
    '[dependency-groups]\nx=[{include-group="missing"}]',
    '[dependency-groups]\nx=[{include-group="y"}]\ny=[{include-group="x"}]',
    '[dependency-groups]\nmy-group=["crewai"]\nmy_group=["langchain"]',
    '[dependency-groups]\nx=[{unsupported="crewai"}]',
    '[tool.poetry.dependencies]\ncrewai=true',
    '[project]\ndependencies=["private @ invalid url SECRET-MARKER"]',
])
def test_invalid_toml_declarations_do_not_yield_partial_evidence(tmp_path, source):
    (tmp_path / "requirements.txt").write_text("langchain\n")
    (tmp_path / "pyproject.toml").write_text(source)
    with pytest.raises(intake.DeclarationError) as error:
        detected(tmp_path)
    assert "SECRET-MARKER" not in str(error.value)


@pytest.mark.parametrize(("filename", "source"), [
    ("pyproject.toml", '[project]\ndynamic=["dependencies"]'),
    ("setup.cfg", '[options]\ninstall_requires=file: dependencies.txt'),
    ("setup.py", 'from setuptools import setup\nsetup(install_requires=load_requirements())'),
    ("setup.py", 'from setuptools import setup\nsetup(**metadata)'),
    ("setup.py", 'import my_backend\nmy_backend.configure()'),
    ("requirements.txt", "-e ."),
    ("requirements.txt", "git+https://example.invalid/langchain#egg=langchain"),
    ("requirements.txt", "./crewai.whl"),
])
def test_dynamic_metadata_requires_explicit_selection(tmp_path, filename, source):
    (tmp_path / filename).write_text(source)
    with pytest.raises(intake.UnsupportedDeclaration, match="--framework"):
        detected(tmp_path)


@pytest.mark.parametrize("include", ["../outside.txt", "/tmp/outside.txt", "https://example.invalid/r.txt", "C:/r.txt", "reqs\\r.txt", "${PRIVATE_PATH}", "~/r.txt"])
def test_includes_cannot_escape_or_expand(tmp_path, include):
    (tmp_path / "requirements.txt").write_text(f"langchain\n-r {include}\n")
    with pytest.raises(intake.DeclarationError):
        detected(tmp_path)


@pytest.mark.parametrize("source", ["-r requirements.txt", "-r missing.txt", "--unexpected=SECRET-MARKER", "-r a b", "langchain --unexpected=secret", "langchain @ invalid url SECRET-MARKER"])
def test_requirement_errors_are_fixed_and_no_partial_detection(tmp_path, source):
    (tmp_path / "requirements.txt").write_text("crewai\n" + source)
    with pytest.raises(intake.DeclarationError) as error:
        detected(tmp_path)
    assert "SECRET-MARKER" not in str(error.value)


def test_detection_does_not_execute_setup_or_expand_environment(tmp_path, monkeypatch):
    sentinel = tmp_path / "executed"
    (tmp_path / "setup.py").write_text(
        f'from setuptools import setup\nfrom pathlib import Path\nPath({str(sentinel)!r}).touch()\n'
        'setup(install_requires=["langchain"])\nraise RuntimeError("must not run")\n'
    )
    (tmp_path / "requirements.txt").write_text("langchain @ https://${PRIVATE_TOKEN}@example.invalid/crewai.whl")
    monkeypatch.setenv("PRIVATE_TOKEN", "crewai")
    assert detected(tmp_path) == [("langchain", ("requirements.txt", "setup.py"))]
    assert not sentinel.exists()


@pytest.mark.parametrize("kind", ["final-link", "dangling-link", "parent-link", "directory", "fifo", "invalid-utf8", "oversized"])
def test_rejects_nonordinary_or_oversized_input(tmp_path, kind):
    target = tmp_path / "requirements.txt"
    if kind in {"final-link", "dangling-link", "parent-link"}:
        actual = tmp_path / "actual"
        actual.mkdir()
        (actual / "base.in").write_text("langchain")
        try:
            if kind == "parent-link":
                (tmp_path / "reqs").symlink_to(actual, target_is_directory=True)
                target.write_text("-r reqs/base.in")
            else:
                target.symlink_to(actual / ("base.in" if kind == "final-link" else "missing"))
        except OSError:
            pytest.skip("platform cannot create symlinks")
    elif kind == "directory":
        target.mkdir()
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("no POSIX FIFO")
        os.mkfifo(target)
    elif kind == "invalid-utf8":
        target.write_bytes(b"langchain\xff")
    else:
        target.write_bytes(b"#" * (intake.MAX_FILE_BYTES + 1))
    with pytest.raises(intake.DeclarationError):
        detected(tmp_path)


@pytest.mark.parametrize("budget", ["MAX_FILES", "MAX_TOTAL_BYTES", "MAX_DIRECTORY_ENTRIES", "MAX_NODES", "MAX_DEPTH", "MAX_REQUIREMENT"])
def test_intake_budgets_are_enforced(tmp_path, monkeypatch, budget):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["langchain"]')
    (tmp_path / "requirements.txt").write_text("crewai")
    monkeypatch.setattr(intake, budget, 1)
    with pytest.raises(intake.DeclarationError):
        detected(tmp_path)


def test_auto_scaffold_ignores_comments_and_fails_before_writes_on_bad_declarations(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("# crewai\nlangchain\n")
    assert integrate_main(["--root", str(tmp_path)]) == 0
    manifest = json.loads((tmp_path / ".dspy-security-bench/integration.json").read_text())
    assert manifest["framework"] == "langchain"
    other = tmp_path / "bad"
    other.mkdir()
    (other / "pyproject.toml").write_text('[project]\ndependencies=["SECRET-MARKER invalid"]')
    assert integrate_main(["--root", str(other)]) == 2
    assert not (other / "dspy_security_target.py").exists()
    assert "SECRET-MARKER" not in capsys.readouterr().err


def test_ambiguous_optional_frameworks_still_require_a_choice(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["langgraph"]\n[project.optional-dependencies]\ntest=["crewai"]')
    assert integrate_main(["--root", str(tmp_path)]) == 2
    assert "multiple frameworks detected" in capsys.readouterr().err
    assert not (tmp_path / "dspy_security_target.py").exists()


def test_detect_inventory_is_read_only_and_can_explain_ambiguity(tmp_path, capsys, monkeypatch):
    (tmp_path / "requirements.txt").write_text("langchain\ncrewai\n")
    monkeypatch.setattr("dspy_security_bench.integrations.cli.integrate_project", lambda *a, **k: pytest.fail("must not scaffold"))
    assert integrate_main(["--root", str(tmp_path), "--detect", "--json"]) == 0
    inventory = json.loads(capsys.readouterr().out)
    assert inventory["mode"] == "declarations_only"
    assert [(item["framework"], item["declarations"]) for item in inventory["detected_frameworks"]] == [
        ("langchain", ["requirements.txt"]), ("crewai", ["requirements.txt"]),
    ]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["requirements.txt"]
    (tmp_path / "requirements.txt").write_text("# langchain\nrequests")
    assert integrate_main(["--root", str(tmp_path), "--detect"]) == 0
    assert "none detected" in capsys.readouterr().out


def test_detect_errors_and_json_flag_do_not_create_targets(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("SECRET-MARKER invalid")
    assert integrate_main(["--root", str(tmp_path), "--detect", "--json"]) == 2
    output = capsys.readouterr()
    assert not output.out and "SECRET-MARKER" not in output.err
    with pytest.raises(SystemExit) as error:
        integrate_main(["--root", str(tmp_path), "--framework", "mcp", "--json"])
    assert error.value.code == 2
    assert not (tmp_path / "dspy_security_target.py").exists()


def test_trace_doctor_uses_same_structural_detection(tmp_path):
    (tmp_path / "requirements.txt").write_text("# crewai\nlangchain\n")
    assert runtime_doctor(tmp_path)["detected_frameworks"] == ["langchain"]


def test_explicit_manifest_can_check_trusted_factory_with_dynamic_project_metadata(tmp_path, monkeypatch):
    integrate_project(get_framework("mcp"), tmp_path, runner="missing:run")
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup(**load_metadata())")

    class Agent:
        name = "trusted"

        def run(self):
            raise AssertionError("never run")

    monkeypatch.setattr("dspy_security_bench.integrations.doctor._load_factory", lambda *_: Agent)
    report = run_doctor(tmp_path)
    assert report.passed and report.factory_calls_attempted == 2
    assert any(check.name == "framework" and check.status == "warn" for check in report.checks)
    (tmp_path / "requirements.txt").write_bytes(b"\xff")
    report = run_doctor(tmp_path)
    assert not report.passed and report.factory_calls_attempted == 0


def test_unsupported_metadata_does_not_hide_other_invalid_inputs(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndynamic=["dependencies"]')
    (tmp_path / "requirements.txt").write_bytes(b"\xff")
    with pytest.raises(intake.DeclarationError) as error:
        detected(tmp_path)
    assert not isinstance(error.value, intake.UnsupportedDeclaration)
