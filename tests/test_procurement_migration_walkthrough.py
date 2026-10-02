"""Execute the migration guide's commands rather than a parallel test-only recipe."""

import shlex
import socket
from pathlib import Path

import pytest

from dspy_security_bench.procurement.cli import main


def test_migration_exercise_replays_exact_documented_commands(tmp_path, monkeypatch, capsys):
    document = (Path(__file__).resolve().parents[1] / "docs" / "migration-evidence-integrity.md").read_text()
    section = document.split("### Run the procurement upgrade exercise\n", 1)[1]
    commands = section.split("```sh\n", 1)[1].split("```", 1)[0].strip().splitlines()
    assert len(commands) == 4

    def forbidden(*args, **kwargs):
        pytest.fail("migration exercise must not contact a network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.chdir(tmp_path)
    for command, expected in zip(commands, (0, 1, 0, 1), strict=True):
        argv = shlex.split(command)
        assert argv[:2] == ["dspy-security-bench", "impact"]
        assert main(argv[2:]) == expected
    output = capsys.readouterr().out
    assert "[NOT ELIGIBLE]" in output
    assert "[INVALID]" in output
    assert "owner review required" in output
