"""Runtime setup must not discover, install, or synchronize the intake project."""

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("review_runtime", ROOT / "actions/review-collection/runtime.py")
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "action-source"
    root.mkdir()
    (root / "uv.lock").write_bytes(b"retained lock bytes\n")
    (root / "pyproject.toml").write_bytes(b"retained project bytes\n")
    return root


def environment(tmp_path):
    return {**os.environ, "RUNNER_OS": "Linux", "RUNNER_TEMP": str(tmp_path),
            "VIRTUAL_ENV": str(tmp_path / "caller-venv"), "PYTHONPATH": str(tmp_path / "caller"),
            "PYTHONHOME": str(tmp_path / "caller"), "UV_PROJECT_ENVIRONMENT": str(tmp_path / "caller-venv"),
            "UV_FROZEN": "true", "UV_NO_INSTALL_PROJECT": "true", "UV_NO_SYNC": "true",
            "UV_CONFIG_FILE": str(tmp_path / "caller.toml"), "UV_CACHE_DIR": str(tmp_path / "cache")}


def fake_install(command, **kwargs):
    python = Path(kwargs["env"]["UV_PROJECT_ENVIRONMENT"]) / "bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"mock interpreter existence only")


def test_exact_locked_install_uses_fresh_environment_and_no_caller_config(source, tmp_path, monkeypatch):
    calls = []
    caller = tmp_path / "caller-venv"
    caller.mkdir()
    (caller / "KEEP").write_bytes(b"caller environment")

    def install(command, **kwargs):
        calls.append((command, kwargs))
        fake_install(command, **kwargs)

    monkeypatch.setattr(RUNTIME.subprocess, "run", install)
    monkeypatch.chdir(tmp_path)  # A caller project must never be discovered.
    (tmp_path / "pyproject.toml").write_text("INVALID CALLER PROJECT")
    results = [RUNTIME.prepare(environment(tmp_path), source) for _ in range(2)]
    assert results[0]["python"] != results[1]["python"]
    assert all(result["dependency-lock-sha256"] == hashlib.sha256(b"retained lock bytes\n").hexdigest() for result in results)
    assert (caller / "KEEP").read_bytes() == b"caller environment"
    assert list(caller.iterdir()) == [caller / "KEEP"]
    for command, options in calls:
        assert command == ["uv", "--no-config", "sync", "--locked", "--no-default-groups", "--no-dev", "--no-editable",
                           "--python", "3.12", "--project", str(source)]
        env = options["env"]
        assert not {"VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME"}.intersection(env)
        assert not {"UV_FROZEN", "UV_NO_INSTALL_PROJECT", "UV_NO_SYNC", "UV_CONFIG_FILE"}.intersection(env)
        assert env["UV_CACHE_DIR"] == str(tmp_path / "cache")
        assert Path(env["UV_PROJECT_ENVIRONMENT"]).parent.parent == tmp_path
        assert env["UV_PROJECT_ENVIRONMENT"] != str(caller)
        assert options["stdin"] == subprocess.DEVNULL and options["check"] and options["timeout"] == 600


@pytest.mark.parametrize("key,value", [("RUNNER_OS", "Windows"), ("RUNNER_TEMP", ""),
                                       ("RUNNER_TEMP", "relative"), ("RUNNER_TEMP", "/tmp/x\ninject=yes"),
                                       ("RUNNER_TEMP", "/tmp/*")])
def test_bad_environment_never_runs_installer(source, tmp_path, monkeypatch, key, value):
    env = environment(tmp_path)
    env[key] = value
    monkeypatch.setattr(RUNTIME.subprocess, "run", lambda *a, **k: pytest.fail("installer must not run"))
    with pytest.raises(ValueError):
        RUNTIME.prepare(env, source)
    assert not list(tmp_path.glob("proofrun-runtime-*"))


@pytest.mark.parametrize("name", ["uv.lock", "pyproject.toml"])
def test_missing_locked_source_does_not_allocate_environment(source, tmp_path, monkeypatch, name):
    (source / name).unlink()
    monkeypatch.setattr(RUNTIME.subprocess, "run", lambda *a, **k: pytest.fail("installer must not run"))
    with pytest.raises(FileNotFoundError):
        RUNTIME.prepare(environment(tmp_path), source)
    assert not list(tmp_path.glob("proofrun-runtime-*"))


@pytest.mark.parametrize("failure", ["installer", "timeout", "interpreter_missing", "lock_changed", "project_changed"])
def test_failed_setup_has_no_ready_result(source, tmp_path, monkeypatch, failure):
    def install(command, **kwargs):
        if failure == "installer":
            raise subprocess.CalledProcessError(1, command)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 600)
        if failure != "interpreter_missing":
            fake_install(command, **kwargs)
        if failure in {"lock_changed", "project_changed"}:
            (source / ("uv.lock" if failure == "lock_changed" else "pyproject.toml")).write_bytes(b"CHANGED")
    monkeypatch.setattr(RUNTIME.subprocess, "run", install)
    with pytest.raises((subprocess.SubprocessError, ValueError)):
        RUNTIME.prepare(environment(tmp_path), source)


def test_main_keeps_setup_errors_out_of_runner_outputs(tmp_path, monkeypatch, capsys):
    def broken(*a, **k):
        raise ValueError("PRIVATE diagnostics")
    monkeypatch.setattr(RUNTIME, "prepare", broken)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "outputs"))
    assert RUNTIME.main() == 2
    assert not (tmp_path / "outputs").exists()
    assert "PRIVATE" not in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="Linux action shell")
@pytest.mark.parametrize("runtime", ["", "/does-not-exist/python"])
def test_review_does_not_fall_back_to_caller_python(tmp_path, runtime):
    from tests.test_collection_review_action import STEP, shell
    env = {**os.environ, "PROOFRUN_REVIEW_PYTHON": runtime, "GITHUB_ACTION_PATH": str(tmp_path)}
    result = shell(STEP["run"], env, tmp_path)
    assert result.returncode == 2 and not result.stdout


@pytest.mark.skipif(sys.version_info[:2] != (3, 12) or shutil.which("uv") is None,
                    reason="real installer contract requires the action's Python 3.12 and uv")
def test_real_installer_rejects_stale_lock_without_cache_or_network_dependencies(tmp_path, monkeypatch):
    source = tmp_path / "minimal"
    source.mkdir()
    text = '[project]\nname = "locked-runtime-fixture"\nversion = "0.1.0"\nrequires-python = ">=3.12"\ndependencies = []\n'
    (source / "pyproject.toml").write_text(text)
    env = {**os.environ, "RUNNER_OS": "Linux", "RUNNER_TEMP": str(tmp_path),
           "UV_OFFLINE": "true", "UV_PYTHON_DOWNLOADS": "never", "UV_CACHE_DIR": str(tmp_path / "cache"),
           "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")}
    subprocess.run(["uv", "--no-config", "lock", "--project", str(source), "--python", sys.executable],
                   env=env, check=True, capture_output=True, timeout=30)
    before = (source / "uv.lock").read_bytes()
    (source / "pyproject.toml").write_text(text.replace("0.1.0", "0.2.0"))
    native_run = subprocess.run

    def capture(*args, **kwargs):
        return native_run(*args, **kwargs, capture_output=True)

    monkeypatch.setattr(RUNTIME.subprocess, "run", capture)
    with pytest.raises(subprocess.CalledProcessError) as error:
        RUNTIME.prepare(env, source)
    assert b"--locked" in error.value.stderr
    assert (source / "uv.lock").read_bytes() == before
