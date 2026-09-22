"""Keep the release wheel smoke isolated from checkout import shortcuts."""

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "installed_smoke", Path(__file__).resolve().parents[1] / "scripts/smoke_installed_package.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def test_cli_smoke_uses_isolated_interpreter_and_bounded_child(tmp_path, monkeypatch):
    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(smoke.subprocess, "run", execute)
    smoke.run_cli(tmp_path, ["scan", "verify", "example.json"], 1)
    command, options = calls[0]
    assert command[:3] == [smoke.sys.executable, "-I", "-c"]
    assert command[3] == smoke.BOOTSTRAP
    assert options["cwd"] == tmp_path
    assert options["timeout"] == 60
    assert options["check"] is False
    compile(smoke.BOOTSTRAP, "<wheel smoke>", "exec")


def test_unexpected_exit_and_timeout_fail_the_smoke(tmp_path, monkeypatch):
    monkeypatch.setattr(smoke.subprocess, "run", lambda *a, **k:
                        SimpleNamespace(returncode=0, stdout="unexpected success", stderr=""))
    with pytest.raises(RuntimeError, match="expected exit 2, got 0"):
        smoke.run_cli(tmp_path, ["scan", "verify", "tampered.json"], 2)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("smoke", 60)

    monkeypatch.setattr(smoke.subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        smoke.run_cli(tmp_path, ["--version"])


def test_bootstrap_blocks_accidental_python_socket_calls():
    assert "socket.socket.connect = offline" in smoke.BOOTSTRAP
    assert "socket.socket.connect_ex = offline" in smoke.BOOTSTRAP
    assert "socket.getaddrinfo = offline" in smoke.BOOTSTRAP
    assert 'origin.get("dir_info", {}).get("editable")' in smoke.BOOTSTRAP
    assert 'sysconfig.get_path("purelib")' in smoke.BOOTSTRAP
    assert 'entry[0].load()(sys.argv[1:])' in smoke.BOOTSTRAP


def test_smoke_cannot_succeed_by_importing_checkout():
    checkout = Path(__file__).resolve().parents[1]
    code = f"import sys; sys.path.insert(0, {str(checkout)!r})\n" + smoke.BOOTSTRAP
    result = subprocess.run([smoke.sys.executable, "-I", "-c", code, "--version"],
                            capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode != 0
    assert "smoke requires the wheel installed" in result.stderr


def test_smoke_exercises_negative_verdicts_and_digest_tampering(monkeypatch):
    calls = []

    def fixture_cli(directory, arguments, expected=0):
        calls.append((arguments, expected))
        if arguments[:2] == ["scan", "demo"]:
            (directory / "demo").mkdir()
            (directory / "demo/before.json").write_text(json.dumps({"evidence_sha256": "1" * 64}))
        if arguments == ["scan", "verify", "tampered.json"]:
            assert json.loads((directory / "tampered.json").read_text()) == {"evidence_sha256": "0" * 64}
        if arguments[0] == "init":
            (directory / ".dspy-security-bench.yaml").write_text("fictional")

    monkeypatch.setattr(smoke, "run_cli", fixture_cli)
    assert smoke.main() == 0
    assert [expected for _, expected in calls] == [0, 0, 0, 1, 0, 1, 2, 0]
