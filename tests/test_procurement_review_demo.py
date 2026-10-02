"""The onboarding handoff teaches real verifier distinctions offline."""

import json
import shlex
import socket

import pytest

from dspy_security_bench.procurement.cli import main
from dspy_security_bench.procurement.repeat import canonical_sha256


def test_documented_walkthrough_is_offline_and_replays_all_exit_codes(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("synthetic walkthrough must not access a network or external model")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    destination = tmp_path / "demo"
    assert main(["review-demo", "--out", str(destination)]) == 0
    assert {p.name for p in destination.iterdir()} == {
        "report.json", "bundle.json", "sharing-review.json", "invalid-bundle.json", "card.svg", "README.md",
    }
    readme = (destination / "README.md").read_text()
    commands = [shlex.split(line)[2:] for line in readme.splitlines()
                if line.startswith("dspy-security-bench impact ")]
    assert len(commands) == 4
    monkeypatch.chdir(destination)
    capsys.readouterr()
    for command, expected in zip(commands, (0, 1, 0, 1), strict=True):
        assert main(command) == expected
    output = capsys.readouterr().out
    assert "[NOT ELIGIBLE]" in output
    assert "[INVALID]" in output
    assert "owner review required" in output
    assert "No external model" in readme
    assert "80% Wilson" in (destination / "card.svg").read_text()
    invalid = json.loads((destination / "invalid-bundle.json").read_text())
    for obj, field in [(invalid, "bundle_sha256"), (invalid["report"], "report_sha256"),
                       (invalid["report"]["trials"][0]["control"], "report_sha256")]:
        assert obj[field] == canonical_sha256({k: v for k, v in obj.items() if k != field})
    assert invalid["report_sha256"] == canonical_sha256(invalid["report"])
    sharing = json.loads((destination / "sharing-review.json").read_text())
    assert sharing["publication_status"] == "owner_review_required"
    assert sharing["inventory"]["tool_arguments"]["object_keys"] > 0


@pytest.mark.parametrize("kind", ["directory", "file", "symlink", "dangling", "missing_parent"])
def test_bad_destinations_stop_before_execution_and_preserve_data(tmp_path, monkeypatch, kind):
    import dspy_security_bench.procurement.review_demo as demo

    def forbidden():
        pytest.fail("invalid output path must stop before running the fixture")

    monkeypatch.setattr(demo, "build_review_demo", forbidden)
    source = tmp_path / "preserve"
    source.write_text("unchanged")
    destination = tmp_path / "output"
    if kind == "directory":
        destination.mkdir()
    elif kind == "file":
        destination.write_text("unchanged")
    elif kind == "symlink":
        destination.symlink_to(source)
    elif kind == "dangling":
        destination.symlink_to(tmp_path / "absent")
    else:
        destination = tmp_path / "absent" / "output"
    assert main(["review-demo", "--out", str(destination)]) == 2
    assert source.read_text() == "unchanged"
    assert not (tmp_path / "absent").exists()
